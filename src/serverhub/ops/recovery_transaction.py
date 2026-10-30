"""Crash-durable transaction core; NOT enrolled in native repair or watchdog yet.

No subprocesses, SQL application mutations, service control or runtime replacement
live here. A separately reviewed independent native adapter is required. In
particular, implementing this core does NOT clear the issue #20 release gate.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import re
import time
from typing import Protocol
import uuid
from contextlib import closing


class TransactionError(RuntimeError):
    pass


class RecoveryAdapter(Protocol):
    """Privileged independent runtime contract, never implemented by a prompt.

    All methods must be idempotent across process death. quiesce must fence ALL
    database and configuration writers, not just HTTP traffic. checkpoint must
    durably capture DB/config/code identities under that fence. verify_restore
    must restore into a fresh isolated database and verify schema, job/audit/OAuth
    identities and configuration checksums. Neither method may mutate live data.

    migrate/activate/probe keep writers fenced. restore_previous must retain the
    failed candidate database/configuration, restore into a new empty database,
    and coordinate old code + configuration + DB selection. It must NEVER clean
    or overwrite a nonempty database. verify_previous proves their compatibility.

    admit_writes may expose writes only to the selected verified release. It is
    the only method allowed to remove the fence. The recovery runtime itself
    must remain pinned and unchanged throughout this transaction.
    """
    def quiesce(self) -> None: ...
    def checkpoint(self, transaction_id: str) -> dict: ...
    def verify_restore(self, checkpoint: dict) -> None: ...
    def migrate(self, transaction_id: str) -> None: ...
    def activate(self, transaction_id: str) -> None: ...
    def probe(self) -> None: ...
    def restore_previous(self, transaction_id: str, checkpoint: dict) -> None: ...
    def verify_previous(self) -> None: ...
    def admit_writes(self, release: str) -> None: ...


class Transaction:
    """Shared process lease plus durable intent history on a local filesystem.

    lock.sqlite is never removed/replaced. Its exclusive SQLite transaction is
    released by the OS on process death. journal.sqlite commits independently
    with synchronous=FULL, so writing a phase never drops the process lease.
    No lease expiry, PID guessing or time-based takeover can race an upgrader.
    Network filesystems are outside the supported deployment contract.
    """
    PHASES = {"prepared", "quiescing", "checkpointing", "verifying", "migrating",
              "activating", "probing", "recovering", "restored", "reverted", "committed", "completed"}
    TRANSITIONS = {
        "prepared": {"quiescing", "recovering"},
        "quiescing": {"checkpointing", "recovering"},
        "checkpointing": {"verifying", "recovering"},
        "verifying": {"migrating", "recovering"},
        "migrating": {"activating", "recovering"},
        "activating": {"probing", "recovering"},
        "probing": {"committed", "recovering"},
        "committed": {"completed"},
        "recovering": {"recovering", "restored"},
        "restored": {"reverted"},
    }

    def __init__(self, state_root: str | Path, *, require_root=True):
        self.root = Path(state_root)
        self.require_root = require_root
        self.journal_path = self.root / "journal.sqlite"
        self._lease = None

    def _protect(self, path):
        for item in (path, *path.parents):
            if item.is_symlink():
                raise TransactionError("unprotected transaction path")
            if self.require_root:
                info = item.stat()
                if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                    raise TransactionError("transaction paths must be root-owned and protected")

    def _file(self, path):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            created = False
        else:
            os.close(fd)
            created = True
        self._protect(path)
        if not path.is_file():
            raise TransactionError("transaction storage must be a regular file")
        if self.require_root and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise TransactionError("transaction files must be private")
        return created

    def __enter__(self):
        if self._lease is not None:
            raise TransactionError("transaction lease already held")
        if not self.root.is_absolute():
            raise TransactionError("transaction path must be absolute")
        if self.require_root and (not hasattr(os, "geteuid") or os.geteuid() != 0):
            raise TransactionError("independent root recovery required")
        # Check ancestors before creating anything through a symlink.
        for item in (self.root, *self.root.parents):
            if item.exists() or item.is_symlink():
                self._protect(item)
                break
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._protect(self.root)
        lock = self.root / "lock.sqlite"
        created_lock = self._file(lock)
        connection = sqlite3.connect(lock, timeout=0, isolation_level=None)
        try:
            connection.execute("BEGIN EXCLUSIVE")
        except sqlite3.Error:
            connection.close()
            raise TransactionError("transaction busy or lock unavailable") from None
        self._lease = connection
        try:
            if created_lock:
                if not self._file(self.journal_path):
                    raise TransactionError("journal exists without its original lock")
                with closing(sqlite3.connect(self.journal_path)) as journal:
                    with journal:
                        journal.execute("PRAGMA synchronous=FULL")
                        journal.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, record TEXT NOT NULL)")
            elif not self.journal_path.is_file() or self.journal_path.stat().st_size == 0:
                raise TransactionError("transaction journal missing; manual inspection required")
            # Validate on entry as well as on every use. Never silently recreate
            # a missing journal following an interrupted transaction.
            self.history()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *args):
        if self._lease is not None:
            self._lease.close()
            self._lease = None

    def _connection(self):
        if self._lease is None:
            raise TransactionError("exclusive transaction lease required")
        self._protect(self.journal_path)
        conn = sqlite3.connect(self.journal_path, timeout=0)
        try:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA journal_mode=DELETE")
            return conn
        except sqlite3.Error:
            conn.close()
            raise TransactionError("transaction journal unavailable or corrupt") from None

    def history(self):
        conn = self._connection()
        try:
            rows = conn.execute("SELECT sequence, record FROM events ORDER BY sequence").fetchall()
            records = []
            for expected, (sequence, raw) in enumerate(rows, 1):
                if sequence != expected:
                    raise ValueError("missing journal event")
                record = json.loads(raw)
                self._validate(record, records[-1] if records else None)
                records.append(record)
            return records
        except (sqlite3.Error, ValueError, TypeError, AttributeError):
            raise TransactionError("transaction journal unavailable or corrupt") from None
        finally:
            conn.close()

    def read(self):
        history = self.history()
        return history[-1] if history else None

    @staticmethod
    def _checkpoint_valid(checkpoint, transaction_id):
        return (isinstance(checkpoint, dict) and set(checkpoint) == {"id", "sha256"}
                and checkpoint["id"] == transaction_id
                and isinstance(checkpoint["sha256"], str)
                and re.fullmatch("[0-9a-f]{64}", checkpoint["sha256"]) is not None)

    def _validate(self, record, previous):
        required = {"format", "id", "phase", "previous", "candidate", "runtime", "checkpoint", "time"}
        if not isinstance(record, dict) or set(record) not in (required, required | {"recover_from"}):
            raise ValueError("invalid journal fields")
        if record["format"] != 1 or record["phase"] not in self.PHASES:
            raise ValueError("invalid journal format/phase")
        if not isinstance(record["id"], str) or not re.fullmatch("[0-9a-f]{32}", record["id"]):
            raise ValueError("invalid transaction identity")
        for key in ("previous", "candidate", "runtime"):
            if not isinstance(record[key], str) or not record[key] or len(record[key]) > 200 or "\0" in record[key]:
                raise ValueError("invalid immutable identity")
        if record["previous"] == record["candidate"]:
            raise ValueError("identical releases")
        if type(record["time"]) not in (int, float) or not math.isfinite(record["time"]):
            raise ValueError("invalid journal time")
        phase = record["phase"]
        checkpoint = record["checkpoint"]
        if checkpoint is not None and not self._checkpoint_valid(checkpoint, record["id"]):
            raise ValueError("invalid checkpoint evidence")
        if phase in {"verifying", "migrating", "activating", "probing", "committed", "completed"} and checkpoint is None:
            raise ValueError("checkpoint required")
        if phase in {"prepared", "quiescing", "checkpointing"} and checkpoint is not None:
            raise ValueError("premature checkpoint")
        recovering = phase in {"recovering", "restored", "reverted"}
        if recovering != ("recover_from" in record):
            raise ValueError("missing or unexpected recovery origin")
        if recovering and record["recover_from"] not in {"prepared", "quiescing", "checkpointing", "verifying", "migrating", "activating", "probing"}:
            raise ValueError("invalid recovery origin")
        if previous is None or previous["phase"] in {"completed", "reverted"}:
            if phase != "prepared" or (previous and previous["id"] == record["id"]):
                raise ValueError("invalid transaction start")
            return
        if phase not in self.TRANSITIONS.get(previous["phase"], set()):
            raise ValueError("invalid phase transition")
        if any(record[key] != previous[key] for key in ("id", "previous", "candidate", "runtime")):
            raise ValueError("changed immutable transaction identity")
        if previous["checkpoint"] is not None and checkpoint != previous["checkpoint"]:
            raise ValueError("changed checkpoint evidence")
        if recovering:
            origin = previous.get("recover_from", previous["phase"])
            if record["recover_from"] != origin:
                raise ValueError("changed recovery origin")

    def _write(self, record):
        try:
            self._validate(record, self.read())
        except (ValueError, TypeError, KeyError):
            raise TransactionError("invalid transaction journal transition") from None
        conn = self._connection()
        try:
            conn.execute("INSERT INTO events (record) VALUES (?)", (json.dumps(record, sort_keys=True),))
            conn.commit()
        except sqlite3.Error:
            raise TransactionError("transaction journal write failed") from None
        finally:
            conn.close()
        return record

    def begin(self, previous: str, candidate: str, runtime: str):
        current = self.read()
        if current is not None and current["phase"] not in {"completed", "reverted"}:
            raise TransactionError("pending transaction must be recovered first")
        if any(not isinstance(v, str) or not v or len(v) > 200 for v in (previous, candidate, runtime)):
            raise TransactionError("invalid immutable release/runtime identity")
        if previous == candidate:
            raise TransactionError("candidate must differ from previous release")
        return self._write({"format": 1, "id": uuid.uuid4().hex, "phase": "prepared",
                            "previous": previous, "candidate": candidate, "runtime": runtime,
                            "checkpoint": None, "time": time.time()})

    def _phase(self, record, phase, **values):
        return self._write(dict(record, phase=phase, time=time.time(), **values))

    def upgrade(self, adapter: RecoveryAdapter, previous: str, candidate: str, runtime: str):
        record = self.begin(previous, candidate, runtime)
        try:
            record = self._phase(record, "quiescing")
            adapter.quiesce()
            record = self._phase(record, "checkpointing")
            checkpoint = adapter.checkpoint(record["id"])
            if not self._checkpoint_valid(checkpoint, record["id"]):
                raise TransactionError("invalid checkpoint evidence")
            record = self._phase(record, "verifying", checkpoint=checkpoint)
            adapter.verify_restore(checkpoint)
            record = self._phase(record, "migrating")
            adapter.migrate(record["id"])
            record = self._phase(record, "activating")
            adapter.activate(record["id"])
            record = self._phase(record, "probing")
            adapter.probe()
            record = self._phase(record, "committed")
            adapter.admit_writes("candidate")
            return self._phase(record, "completed")
        except Exception:
            # Retain the last intent and checkpoint. Never persist exception
            # strings: drivers often embed secrets in them. A separate caller
            # invokes recovery under the same lease, not an implicit downgrade.
            raise TransactionError("upgrade incomplete; recovery required") from None

    def recover(self, adapter: RecoveryAdapter):
        record = self.read()
        if record is None:
            return {"phase": "idle"}
        if record["phase"] in {"reverted", "completed"}:
            return record
        try:
            if record["phase"] == "committed":
                # Writes may already have arrived. Never restore a checkpoint.
                adapter.admit_writes("candidate")
                return self._phase(record, "completed")
            if record["phase"] == "restored":
                adapter.admit_writes("previous")
                return self._phase(record, "reverted")
            original = record.get("recover_from", record["phase"])
            record = self._phase(record, "recovering", recover_from=original)
            adapter.quiesce()
            if original in {"migrating", "activating", "probing"}:
                if not record["checkpoint"]:
                    raise TransactionError("missing verified checkpoint")
                adapter.verify_restore(record["checkpoint"])
                adapter.restore_previous(record["id"], record["checkpoint"])
            adapter.verify_previous()
            # Persist before opening writes; a retry must not repeat restore.
            record = self._phase(record, "restored")
            adapter.admit_writes("previous")
            return self._phase(record, "reverted")
        except Exception:
            raise TransactionError("transaction incomplete; recovery required") from None
