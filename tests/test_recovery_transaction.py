"""Synthetic transaction tests; no services, real backup or PostgreSQL access."""
import json
import os
from pathlib import Path
import subprocess
import sys
import sqlite3

import pytest


def core():
    # Import within tests so RED reports the missing implementation per test.
    from serverhub.ops.recovery_transaction import Transaction, TransactionError
    return Transaction, TransactionError


class FixtureAdapter:
    """Idempotent synthetic database/config/code boundary, independent of the journal."""
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail
        self.code = self.database = self.configuration = "previous"
        self.runtime = "independent-runtime"
        self.writers = True
        self.checkpoint_state = None
        self.retained_candidate = None

    def call(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError("injected private connection detail")

    def quiesce(self):
        self.call("quiesce")
        self.writers = False

    def checkpoint(self, transaction_id):
        assert not self.writers
        self.call("checkpoint")
        self.checkpoint_state = (self.database, self.configuration)
        return {"id": transaction_id, "sha256": "a" * 64}

    def verify_restore(self, checkpoint):
        assert not self.writers
        self.call("verify_restore")
        assert checkpoint["sha256"] == "a" * 64

    def migrate(self, transaction_id):
        assert not self.writers
        self.database = "candidate"  # failure may occur after DB commit
        self.call("migrate")

    def activate(self, transaction_id):
        assert not self.writers
        self.code = self.configuration = "candidate"
        self.call("activate")

    def probe(self):
        assert not self.writers
        self.call("probe")

    def restore_previous(self, transaction_id, checkpoint):
        assert not self.writers
        self.call("restore_previous")
        if self.retained_candidate is None:
            self.retained_candidate = self.database
        self.database, self.configuration = self.checkpoint_state
        self.code = "previous"

    def verify_previous(self):
        assert not self.writers
        self.call("verify_previous")
        assert (self.code, self.database, self.configuration) == ("previous",) * 3

    def admit_writes(self, release):
        self.call("admit_" + release)
        self.writers = True


def new(tmp_path):
    cls, _ = core()
    return cls(tmp_path / "state", require_root=False)


def test_success_commits_before_admitting_writes(tmp_path):
    tx = new(tmp_path)
    adapter = FixtureAdapter()
    with tx:
        result = tx.upgrade(adapter, "previous", "candidate", "runtime-digest")
        assert result["phase"] == "completed"
        assert tx.read()["phase"] == "completed"
    assert adapter.calls == ["quiesce", "checkpoint", "verify_restore", "migrate", "activate", "probe", "admit_candidate"]
    assert adapter.runtime == "independent-runtime"
    assert adapter.writers


@pytest.mark.parametrize("failure", ["quiesce", "checkpoint", "verify_restore", "migrate", "activate", "probe"])
def test_failure_retains_checkpoint_and_can_recover_from_new_process_state(tmp_path, failure):
    tx = new(tmp_path)
    adapter = FixtureAdapter(failure)
    with tx:
        with pytest.raises(core()[1], match="recovery required") as error:
            tx.upgrade(adapter, "previous", "candidate", "runtime-digest")
        assert "private" not in str(error.value)
    adapter.fail = None
    with new(tmp_path) as recovery:
        assert recovery.recover(adapter)["phase"] == "reverted"
        count = len(adapter.calls)
        assert recovery.recover(adapter)["phase"] == "reverted"
        assert len(adapter.calls) == count
    assert adapter.database == adapter.code == adapter.configuration == "previous"
    assert adapter.runtime == "independent-runtime"
    assert adapter.writers


def test_failed_recovery_never_admits_writes_or_discards_evidence(tmp_path):
    adapter = FixtureAdapter("probe")
    with new(tmp_path) as tx:
        with pytest.raises(core()[1]):
            tx.upgrade(adapter, "previous", "candidate", "runtime-digest")
        checkpoint = tx.read()["checkpoint"]
        adapter.fail = "restore_previous"
        with pytest.raises(core()[1], match="recovery required"):
            tx.recover(adapter)
        assert tx.read()["checkpoint"] == checkpoint
        assert not adapter.writers
        assert "admit_previous" not in adapter.calls
        adapter.fail = None
        assert tx.recover(adapter)["phase"] == "reverted"


def test_postcommit_failure_can_only_resume_candidate(tmp_path):
    adapter = FixtureAdapter("admit_candidate")
    with new(tmp_path) as tx:
        with pytest.raises(core()[1]):
            tx.upgrade(adapter, "previous", "candidate", "runtime-digest")
        assert tx.read()["phase"] == "committed"
        adapter.fail = None
        assert tx.recover(adapter)["phase"] == "completed"
        assert "restore_previous" not in adapter.calls
        assert adapter.database == "candidate"


def test_pending_transaction_cannot_be_overwritten(tmp_path):
    adapter = FixtureAdapter("migrate")
    with new(tmp_path) as tx:
        with pytest.raises(core()[1]):
            tx.upgrade(adapter, "previous", "candidate", "runtime-digest")
        with pytest.raises(core()[1], match="pending"):
            tx.upgrade(adapter, "previous", "another", "runtime-digest")


def test_methods_require_exclusive_lease(tmp_path):
    tx = new(tmp_path)
    with pytest.raises(core()[1], match="lease"):
        tx.read()


def test_journal_corruption_fails_closed(tmp_path):
    tx = new(tmp_path)
    with tx:
        tx.journal_path.write_bytes(b"not a database")
        with pytest.raises(core()[1], match="journal"):
            tx.recover(FixtureAdapter())


def test_exclusive_lease_and_durable_phase_survive_process_kill(tmp_path):
    cls, error = core()
    script = '''
import sys, time
from serverhub.ops.recovery_transaction import Transaction
with Transaction(sys.argv[1], require_root=False) as tx:
    tx.begin("previous", "candidate", "runtime-digest")
    print("ready", flush=True)
    time.sleep(60)
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    process = subprocess.Popen([sys.executable, "-c", script, str(tmp_path / "state")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        assert process.stdout.readline().strip() == "ready", process.stderr.read() if process.poll() is not None else "child did not initialize"
        with pytest.raises(error, match="busy"):
            with cls(tmp_path / "state", require_root=False):
                pytest.fail("second process acquired lease")
        process.kill()
        process.wait(timeout=10)
        with cls(tmp_path / "state", require_root=False) as recovery:
            assert recovery.read()["phase"] == "prepared"
            assert recovery.read()["runtime"] == "runtime-digest"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def test_every_intent_is_retained_in_history(tmp_path):
    with new(tmp_path) as tx:
        tx.upgrade(FixtureAdapter(), "previous", "candidate", "runtime-digest")
        history = tx.history()
        assert [event["phase"] for event in history] == ["prepared", "quiescing", "checkpointing", "verifying", "migrating", "activating", "probing", "committed", "completed"]
        assert all(json.loads(json.dumps(event)) == event for event in history)


def test_recovery_retries_admission_without_repeating_restore(tmp_path):
    adapter = FixtureAdapter("probe")
    with new(tmp_path) as tx:
        with pytest.raises(core()[1]):
            tx.upgrade(adapter, "previous", "candidate", "runtime-digest")
        adapter.fail = "admit_previous"
        with pytest.raises(core()[1]):
            tx.recover(adapter)
        restores = adapter.calls.count("restore_previous")
        adapter.fail = None
        tx.recover(adapter)
        assert adapter.writers
        assert adapter.calls.count("restore_previous") == restores


def test_unfinished_postcommit_admission_cannot_be_overwritten(tmp_path):
    adapter = FixtureAdapter("admit_candidate")
    with new(tmp_path) as tx:
        with pytest.raises(core()[1]):
            tx.upgrade(adapter, "previous", "candidate", "runtime-digest")
        with pytest.raises(core()[1], match="pending"):
            tx.begin("candidate", "next", "runtime-digest")


@pytest.mark.parametrize("damage", ["bare_commit", "identity", "checkpoint", "origin", "transition"])
def test_logically_corrupt_journal_never_calls_adapter(tmp_path, damage):
    with new(tmp_path) as tx:
        record = tx.begin("previous", "candidate", "runtime-digest")
        if damage == "bare_commit":
            record = {"format": 1, "phase": "committed"}
        elif damage == "identity":
            record["id"] = ""
        elif damage == "checkpoint":
            record.update(phase="migrating", checkpoint={"id": record["id"], "sha256": "x" * 64})
        elif damage == "origin":
            record.update(phase="recovering", recover_from="invented")
        else:
            record.update(phase="committed", checkpoint={"id": record["id"], "sha256": "a" * 64})
        with sqlite3.connect(tx.journal_path) as conn:
            conn.execute("INSERT INTO events(record) VALUES (?)", (json.dumps(record),))
        adapter = FixtureAdapter()
        with pytest.raises(core()[1], match="journal"):
            tx.recover(adapter)
        assert adapter.calls == []


def test_lost_journal_cannot_be_silently_reinitialized(tmp_path):
    tx = new(tmp_path)
    with tx:
        tx.begin("previous", "candidate", "runtime-digest")
    tx.journal_path.unlink()
    with pytest.raises(core()[1], match="journal"):
        with new(tmp_path):
            pytest.fail("lost pending journal was reinitialized")


@pytest.mark.parametrize("kill_at", ["quiesce", "checkpoint", "verify_restore", "migrate", "activate", "probe", "admit_writes", "restore_previous", "verify_previous", "admit_previous"])
def test_process_death_after_each_effect_recovers_from_disk(tmp_path, kill_at):
    cls, _ = core()
    # This child persists its synthetic DB/config fixture separately from the
    # transaction journal. The parent creates a NEW adapter from that disk state.
    script = '''
import json, runpy, sys, time
from pathlib import Path
from serverhub.ops.recovery_transaction import Transaction, TransactionError
Fixture = runpy.run_path(sys.argv[1])["FixtureAdapter"]
kill_at = sys.argv[3]
recovery_test = kill_at in {"restore_previous", "verify_previous", "admit_previous"}
class DiskAdapter(Fixture):
    recovering = False
    def __getattribute__(self, name):
        method = super().__getattribute__(name)
        if name not in {"quiesce", "checkpoint", "verify_restore", "migrate", "activate", "probe", "admit_writes", "restore_previous", "verify_previous"}:
            return method
        def effect(*args):
            result = method(*args)
            path = Path(sys.argv[2]) / "fixture.json"
            path.write_text(json.dumps(self.__dict__))
            label = "admit_previous" if name == "admit_writes" and args == ("previous",) else name
            if label == kill_at and self.recovering == recovery_test:
                print("ready", flush=True)
                time.sleep(60)
            return result
        return effect
adapter = DiskAdapter("probe" if recovery_test else None)
with Transaction(Path(sys.argv[2]) / "state", require_root=False) as tx:
    try:
        tx.upgrade(adapter, "previous", "candidate", "runtime-digest")
    except TransactionError:
        if not recovery_test:
            raise
    if recovery_test:
        adapter.fail = None
        adapter.recovering = True
        tx.recover(adapter)
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    process = subprocess.Popen([sys.executable, "-c", script, str(Path(__file__).resolve()), str(tmp_path), kill_at], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        assert process.stdout.readline().strip() == "ready", process.stderr.read() if process.poll() is not None else "child did not reach effect"
        process.kill()
        process.wait(timeout=10)
        adapter = FixtureAdapter()
        adapter.__dict__.update(json.loads((tmp_path / "fixture.json").read_text()))
        with cls(tmp_path / "state", require_root=False) as tx:
            result = tx.recover(adapter)
            if kill_at == "admit_writes":
                assert result["phase"] == "completed"
                assert adapter.database == adapter.code == "candidate"
                assert "restore_previous" not in adapter.calls
            else:
                assert result["phase"] == "reverted"
                assert adapter.database == adapter.code == adapter.configuration == "previous"
            assert adapter.writers
            assert adapter.runtime == "independent-runtime"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
