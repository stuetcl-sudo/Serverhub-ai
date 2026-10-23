"""Encrypted, offline-consistent Docker backups and isolated restores.

Only root-enrolled named plans are accepted by the broker. No model-supplied paths,
commands, credentials, live-volume copy or destructive in-place restore exists.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .discovery import command


class DockerBackupError(RuntimeError):
    pass


def digest(path, heartbeat=lambda: None):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
            heartbeat()
    return value.hexdigest()


def protected(path, *, create=False):
    path = Path(path)
    if not path.is_absolute():
        raise DockerBackupError('Absolute protected path required')
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for part in (path, *path.parents):
        meta = part.lstat()
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise DockerBackupError(f'Unsafe protected path: {part} (uid={meta.st_uid}, mode={oct(meta.st_mode & 0o777)})')
    return path


def atomic(path, data):
    lock_path = path.with_suffix('.lock')
    with open(lock_path, 'a', opener=lambda name, flags: os.open(name, flags | os.O_NOFOLLOW, 0o600)) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists() and json.loads(path.read_text()).get('state') == 'reverted' and data.get('state') != 'reverted':
            raise DockerBackupError('Independent recovery already reverted this transaction')
        temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
        with open(temporary, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as out:
            json.dump(data, out, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)


def crypt_file(source, target, key, *, decrypt=False, heartbeat=lambda: None):
    """Streaming AES-256-GCM; authentication must finish before extraction/use."""
    with Path(source).open('rb') as inp, Path(target).open('xb') as out:
        os.chmod(target, 0o600)
        if decrypt:
            if inp.read(5) != b'SHBG1':
                raise DockerBackupError('Unknown encrypted artifact format')
            nonce = inp.read(12)
            size = Path(source).stat().st_size
            inp.seek(-16, os.SEEK_END)
            tag = inp.read(16)
            inp.seek(17)
            remaining = size - 33
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        else:
            nonce = secrets.token_bytes(12)
            out.write(b'SHBG1' + nonce)
            remaining = Path(source).stat().st_size
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        while remaining:
            data = inp.read(min(1024 * 1024, remaining))
            if not data:
                raise DockerBackupError('Truncated artifact')
            out.write(cipher.update(data))
            remaining -= len(data)
            heartbeat()
        out.write(cipher.finalize())
        if not decrypt:
            out.write(cipher.tag)
        out.flush()
        os.fsync(out.fileno())


def binary_docker(arguments, path, *, timeout=1800, heartbeat=lambda: None):
    # Binary exports never pass through text decoding, argv interpolation or logs.
    with Path(path).open('xb') as out:
        os.chmod(path, 0o600)
        try:
            process = subprocess.Popen(['/usr/bin/docker', *arguments], stdout=out, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent'})
            deadline = time.monotonic() + timeout
            try:
                while process.poll() is None:
                    heartbeat()
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(arguments, timeout)
                    time.sleep(.2)
                if process.returncode:
                    raise subprocess.CalledProcessError(process.returncode, arguments)
            finally:
                if process.poll() is None:
                    import signal
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        except (OSError, subprocess.SubprocessError) as error:
            raise DockerBackupError('Docker export failed or exceeded its deadline') from error


def tree_manifest(path, heartbeat=lambda: None):
    path = Path(path)
    result = {}
    nodes = [path]
    if path.is_dir():
        nodes += sorted(path.rglob('*'))
    if len(nodes) > 100000:
        raise DockerBackupError('Storage entry count exceeds backup bound')
    for child in nodes:
        relative = '.' if child == path else str(child.relative_to(path))
        if child.is_symlink():
            if not child.resolve().is_relative_to(path.resolve()):
                raise DockerBackupError('External storage symlink requires an explicit application adapter')
            result[relative] = {'link': os.readlink(child)}
        elif child.is_file():
            result[relative] = {'sha256': digest(child, heartbeat), 'size': child.stat().st_size}
        elif child.is_dir():
            result[relative] = {'directory': True}
        else:
            raise DockerBackupError('Special storage files require an application-specific backup adapter')
        heartbeat()
    return result


class DockerBackups:
    def __init__(self, config, target):
        if os.geteuid() != 0:
            raise DockerBackupError('Root broker required')
        if not isinstance(target, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', target):
            raise DockerBackupError('Invalid named backup plan')
        self.plan = config.get('docker_backup_plans', {}).get(target)
        if not isinstance(self.plan, dict):
            raise DockerBackupError('Backup plan not enrolled by root')
        self.target = target
        self.state = protected(config.get('operations_state', '/var/lib/serverhub-broker/operations'), create=True)
        self.key_path = protected(self.plan['key_file'])
        if self.key_path.stat().st_mode & 0o077:
            raise DockerBackupError('Backup encryption key must be root-only')
        self.key = self.key_path.read_bytes()
        if len(self.key) != 32:
            raise DockerBackupError('Backup key must contain exactly 32 random bytes')
        self.destination = Path(self.plan.get('destination', '/mnt/storage/ServerHub-Backups'))
        if not self.destination.is_absolute() or not self.destination.is_dir():
            raise DockerBackupError('Backup destination must exist and be mounted/configured explicitly')
        required_mount = self.plan.get('required_mount')
        if required_mount:
            mount = Path(required_mount)
            if not mount.is_absolute() or not self.destination.is_relative_to(mount) or not os.path.ismount(mount):
                raise DockerBackupError('Required backup mount is unavailable; refusing OS-disk fallback')
        elif self.plan.get('allow_system_disk') is not True:
            mount = self.destination
            while not os.path.ismount(mount) and mount != mount.parent:
                mount = mount.parent
            if mount == Path('/'):
                raise DockerBackupError('Backup destination is on the OS filesystem; enroll an actual mount or explicitly allow_system_disk')
        # NTFS may use synthetic POSIX ownership. Encryption/HMAC isolate contents,
        # but deletion resistance still requires a protected mount/off-host copy.
        if self.plan.get('allow_ntfs') is not True:
            protected(self.destination)
        elif self.destination.is_symlink() or any(p.is_symlink() for p in self.destination.parents):
            raise DockerBackupError('Symlinked backup destinations are forbidden')
        self.lock = (self.state / 'docker-backup.lock').open('a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def close(self):
        self.lock.close()

    def inspect(self, names):
        return json.loads(command('docker', 'inspect', *names, timeout=30))

    def _manifest(self, path):
        raw = json.loads((path / 'manifest.json').read_text())
        signature = raw.pop('hmac_sha256')
        actual = hmac.new(self.key, json.dumps(raw, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, actual) or raw['target'] != self.target:
            raise DockerBackupError('Backup manifest authentication failed')
        for name, metadata in raw['files'].items():
            if Path(name).name != name or not re.fullmatch(r'[a-z0-9_.-]+', name):
                raise DockerBackupError('Invalid backup artifact name')
            artifact = path / name
            if artifact.is_symlink() or artifact.stat().st_size != metadata['size'] or digest(artifact) != metadata['sha256']:
                raise DockerBackupError('Backup SHA-256 verification failed')
        return raw

    def path(self, backup_id):
        if not isinstance(backup_id, str) or not re.fullmatch(r'[0-9a-f]{32}', backup_id):
            raise DockerBackupError('Invalid backup identifier')
        path = self.destination / backup_id
        if path.is_symlink() or not path.is_dir():
            raise DockerBackupError('Backup not found')
        return path

    def verify(self, backup_id):
        data = self._manifest(self.path(backup_id))
        return {**data, 'verified': True, 'verification': 'Authenticated manifest and all encrypted artifact SHA-256 values; restore drill is separate'}

    def list(self):
        results = []
        for path in sorted(self.destination.iterdir()):
            if path.is_dir() and not path.is_symlink() and re.fullmatch(r'[0-9a-f]{32}', path.name):
                try:
                    results.append(self.verify(path.name))
                except (DockerBackupError, OSError, ValueError, KeyError):
                    results.append({'id': path.name, 'verified': False, 'error': 'Unverifiable backup; retained'})
        return {'backups': results, 'target': self.target}

    def _source(self, value):
        path = Path(value)
        forbidden = ('/etc', '/root', '/proc', '/sys', '/dev', '/run', '/opt/serverhub', '/var/lib/serverhub-broker', '/var/backups/serverhub', '/var/lib/serverhub-api', '/var/lib/serverhub-worker', '/var/lib/serverhub-node', '/var/lib/serverhub-recovery', '/var/lib/serverhub-release')
        if not path.is_absolute() or any(part.is_symlink() for part in (path,*path.parents)) or any(path.is_relative_to(p) for p in forbidden):

            raise DockerBackupError('Sensitive or symlinked backup source rejected')
        roots = [Path(root) for root in self.plan.get('allowed_bind_roots', [])]
        if not any(path.is_relative_to(root) and root != Path('/') for root in roots):
            raise DockerBackupError('Bind/Compose source outside root-enrolled backup roots')
        return path

    def create(self):
        names = self.plan.get('containers', [])
        if not names or not all(isinstance(n, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', n) for n in names):
            raise DockerBackupError('Plan requires exact container names')
        containers = self.inspect(names)
        for item in containers:
            pid=(item.get('State') or {}).get('Pid',0)
            if isinstance(pid,int) and pid>0:
                try:
                    fields={line.split(':',1)[0]:line.split(':',1)[1].split() for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line}
                    host_uid,host_gid=int(fields['Uid'][1]),int(fields['Gid'][1])
                    def mapped(kind,value):
                        for row in Path(f'/proc/{pid}/{kind}_map').read_text().splitlines():
                            inside,outside,length=map(int,row.split())
                            if outside<=value<outside+length:
                                return inside+value-outside
                        raise ValueError('Unmapped runtime identity')
                    uid,gid=mapped('uid',host_uid),mapped('gid',host_gid)
                    if uid>0:
                        item['ServerHubRuntimeUser']=str(uid)+':'+str(gid)
                except (OSError,KeyError,ValueError):
                    pass  # Config.User or an explicit restore_users contract remains authoritative.
        sources, mounts, compose = {}, {}, {}
        for container in containers:
            for mount in container.get('Mounts', []):
                if mount['Type'] not in {'bind', 'volume'}:
                    continue
                source = Path(mount['Source'])
                if mount['Type'] == 'bind':
                    source = self._source(source)
                else:
                    protected(source.parent)
                    if source.is_symlink() or not source.is_dir():
                        raise DockerBackupError('Named volume data unavailable on this host')
                label = 'data-' + hashlib.sha256(str(source).encode()).hexdigest()[:24]
                sources[label] = source
                mounts.setdefault(container['Id'], []).append({**mount, 'artifact': label})
            labels = container.get('Config', {}).get('Labels') or {}
            for filename in labels.get('com.docker.compose.project.config_files', '').split(','):
                if filename:
                    path = self._source(filename)
                    compose[str(path)] = path.read_text()
                    env = path.parent / '.env'
                    if env.is_file():
                        compose[str(env)] = self._source(env).read_text()
        all_ids = command('docker', 'ps', '-aq').split()
        selected = {item['Id'] for item in containers}
        for other in self.inspect(all_ids) if all_ids else []:
            if other['Id'] not in selected and other['State']['Running'] and any(
                    m.get('RW') and Path(m.get('Source', '')) in sources.values() for m in other.get('Mounts', [])):
                raise DockerBackupError('Shared storage has an unselected running writer; include it in the plan')
        # Upper bound counts apparent file sizes + complete container root/image sizes.
        # Do not rely on compressed-size guesses or sparse allocation for capacity.
        amount = 64 * 1024**2
        for path in sources.values():
            if path.is_dir():
                for base, dirs, files in os.walk(path, followlinks=False):
                    for name in files:
                        amount += (Path(base) / name).lstat().st_size + 4096
            else:
                amount += path.stat().st_size + 4096
        for item in containers:
            sized = json.loads(command('docker', 'inspect', '--size', item['Id']))[0]
            amount += int(sized.get('SizeRootFs', 0)) + 16 * 1024**2
            if self.plan.get('include_images'):
                amount += json.loads(command('docker', 'image', 'inspect', item['Image']))[0]['Size']
        amount = int(amount * 1.25)
        if any(shutil.disk_usage(path).free < amount for path in (self.destination, self.state)):
            raise DockerBackupError(f'Insufficient backup capacity; conservative required bytes={amount}')
        backup_id = uuid.uuid4().hex
        stage = self.state / backup_id
        stage.mkdir(mode=0o700)
        finalizing = self.destination / ('.partial-' + backup_id)
        finalizing.mkdir(mode=0o700)
        running = [item['Id'] for item in containers if item['State']['Running']]
        journal = {'kind': 'docker_start', 'state': 'armed', 'containers': running, 'deadline': time.time() + 300}
        journal_path = self.state / (backup_id + '.json')
        atomic(journal_path, journal)
        last_heartbeat = [0.0]
        def heartbeat():
            if time.monotonic() - last_heartbeat[0] < 5:
                return
            last_heartbeat[0] = time.monotonic()
            journal['deadline'] = time.time() + 300
            atomic(journal_path, journal)
        try:
            if running:
                for name in reversed(running):
                    command('docker', 'stop', '--time', '60', name, timeout=90)
            for item in self.inspect(names):
                state = item['State']
                database = re.search(r'postgres|mariadb|mysql|redis|mongo|clickhouse', item['Config'].get('Image', ''), re.I)
                if state['Running'] or state.get('OOMKilled') or (item['Id'] in running and state.get('ExitCode') not in ({0} if database else {0, 143})):
                    raise DockerBackupError('Container did not quiesce cleanly; refusing database-consistency claim')
            metadata = {'containers': containers, 'mounts': mounts, 'compose': compose, 'data_checksums': {}}
            (stage / 'metadata.json').write_text(json.dumps(metadata))
            for label, source in sources.items():
                heartbeat()
                with tarfile.open(stage / (label + '.tar'), 'w', dereference=False) as out:
                    out.add(source, arcname='data', recursive=True, filter=lambda member: (heartbeat(), member)[1])
                metadata['data_checksums'][label] = tree_manifest(source, heartbeat)
            (stage / 'metadata.json').write_text(json.dumps(metadata))
            for index, item in enumerate(containers):
                heartbeat()
                binary_docker(['export', item['Id']], stage / f'container-{index}.tar', heartbeat=heartbeat)
                if self.plan.get('include_images'):
                    binary_docker(['image', 'save', item['Image']], stage / f'image-{index}.tar', heartbeat=heartbeat)
            files = {}
            for source in sorted(stage.iterdir()):
                target = finalizing / (source.name + '.enc')
                crypt_file(source, target, self.key, heartbeat=heartbeat)
                files[target.name] = {'size': target.stat().st_size, 'sha256': digest(target)}
            manifest = {'format': 1, 'id': backup_id, 'target': self.target, 'created_at': time.time(),
                        'consistency': 'offline_clean_shutdown', 'container_count': len(containers), 'files': files,
                        'estimated_required_bytes': amount, 'encryption': 'AES-256-GCM',
                        'limitations': ['Host processes writing bind mounts must be quiesced separately', 'Restore is isolated; no source data is overwritten']}
            manifest['hmac_sha256'] = hmac.new(self.key, json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
            atomic(finalizing / 'manifest.json', manifest)
            heartbeat()
            os.replace(finalizing, self.destination / backup_id)
            result = self.verify(backup_id)
        finally:
            # Leave the armed journal intact if restart/verification fails. The
            # independent watchdog retries starting only these recorded IDs.
            if running:
                from .broker import _wait_container
                for name in running:
                    command('docker', 'start', name, timeout=60)
                    _wait_container(name)
            journal['state'] = 'committed'
            atomic(journal_path, journal)
            shutil.rmtree(stage, ignore_errors=True)
            if finalizing.exists():
                shutil.rmtree(finalizing)
        self.rotate()
        return result

    def rotate(self):
        keep = self.plan.get('retention_keep')
        if keep is None:
            return  # Absence of policy must NEVER mean deletion.
        if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
            raise DockerBackupError('Retention must explicitly keep at least one verified backup')
        valid = [b for b in self.list()['backups'] if b.get('verified')]
        for backup in sorted(valid, key=lambda x: x['created_at'], reverse=True)[keep:]:
            shutil.rmtree(self.path(backup['id']))

    def restore(self, backup_id, *, apply=False):
        manifest = self._manifest(self.path(backup_id))
        prefix = 'serverhub-restore-' + uuid.uuid4().hex[:12]
        if not apply:
            return {'backup_id': backup_id, 'verified': True, 'mode': 'isolated_restore_plan', 'target': self.target,
                    'overwrites_source': False, 'network': 'new internal Docker network', 'container_count': manifest['container_count']}
        if self.plan.get('allow_isolated_restore') is not True:
            raise DockerBackupError('Isolated restore not explicitly enrolled')
        # Reserve plaintext plus extracted Docker data before decrypting anything.
        docker_root=Path(json.loads(command('docker','info','--format','{{json .DockerRootDir}}')))
        required_by_device={}
        for directory in (self.state,docker_root):
            device=directory.stat().st_dev
            required_by_device[device]=required_by_device.get(device,0)+manifest['estimated_required_bytes']
        for directory in (self.state,docker_root):
            if shutil.disk_usage(directory).free < required_by_device[directory.stat().st_dev]:
                raise DockerBackupError('Insufficient restore capacity for plaintext and extracted data')
        stage = self.state / prefix
        stage.mkdir(mode=0o700)
        created, volumes, network = [], [], None
        try:
            for filename in manifest['files']:
                if filename.startswith('image-'):
                    continue
                crypt_file(self.path(backup_id) / filename, stage / filename[:-4], self.key, decrypt=True)
            metadata = json.loads((stage / 'metadata.json').read_text())
            if shutil.disk_usage(self.state).free < manifest['estimated_required_bytes']:
                raise DockerBackupError('Insufficient restore staging capacity')
            for index, item in enumerate(metadata['containers']):
                if item.get('HostConfig', {}).get('Privileged'):
                    raise DockerBackupError('Privileged container restore requires a separate reviewed deployment')
                # Validate before creating any resources; no host bind mounts restored.
                for mount in metadata['mounts'].get(item['Id'], []):
                    if not mount['Destination'].startswith('/') or mount['Destination'] == '/':
                        raise DockerBackupError('Invalid restore mount')
            network = command('docker', 'network', 'create', '--internal', prefix).strip()
            artifacts = {}
            for index, source in enumerate(sorted({m['artifact'] for mounts in metadata['mounts'].values() for m in mounts})):
                volume = command('docker', 'volume', 'create', f'{prefix}-{index}').strip()
                volumes.append(volume)
                target = Path(json.loads(command('docker', 'volume', 'inspect', volume))[0]['Mountpoint'])
                with tarfile.open(stage / (source + '.tar')) as archive:
                    # Python's data filter rejects absolute paths, devices and
                    # escaping links, while preserving safe permissions/timestamps.
                    def confined_member(member, destination):
                        cleaned = tarfile.data_filter(member, destination)
                        if cleaned is not None:
                            return cleaned.replace(mode=member.mode & 0o777, uid=member.uid, gid=member.gid, uname=None, gname=None)
                        return None
                    archive.extractall(target, filter=confined_member)
                if tree_manifest(target / 'data') != metadata['data_checksums'][source]:
                    raise DockerBackupError('Restored storage content verification failed')
                # Mounts must point at extracted data, not the archive's wrapper.
                artifacts[source] = (volume, target)
            for index, item in enumerate(metadata['containers']):
                image = command('docker', 'import', str(stage / f'container-{index}.tar'), timeout=300).strip()
                cfg = item['Config']
                envfile = stage / f'{index}.env'
                envfile.write_text('\n'.join(cfg.get('Env') or []) + '\n')
                argv = ['create', '--name', f'{prefix}-{index}', '--network', network, '--cap-drop', 'ALL',
                        '--security-opt', 'no-new-privileges', '--env-file', str(envfile)]
                restore_user=(self.plan.get('restore_users') or {}).get(item['Name'].lstrip('/'))
                if restore_user is not None and not re.fullmatch(r'[1-9][0-9]*:[0-9]+',str(restore_user)):
                    raise DockerBackupError('Enrolled restore user must be a numeric nonroot UID:GID')
                user=restore_user or cfg.get('User') or item.get('ServerHubRuntimeUser')
                if user:
                    argv += ['--user',user]
                if cfg.get('WorkingDir'):
                    argv += ['--workdir', cfg['WorkingDir']]
                for alias in {item['Name'].lstrip('/'), (cfg.get('Labels') or {}).get('com.docker.compose.service', '')} - {''}:
                    argv += ['--network-alias', alias]
                for mount in metadata['mounts'].get(item['Id'], []):
                    volume, target = artifacts[mount['artifact']]
                    # Docker volume-subpath retains original file/dir at data/.
                    specification = (f'type=volume,src={volume},dst={mount["Destination"]},volume-subpath=data'
                        if (target / 'data').is_dir() else f'type=bind,src={target / "data"},dst={mount["Destination"]}')
                    argv += ['--mount', specification + (',readonly' if not mount.get('RW') else '')]
                health = cfg.get('Healthcheck') or {}
                if health.get('Test', [None])[0] == 'CMD-SHELL':
                    argv += ['--health-cmd', health['Test'][1], '--health-interval', '1s', '--health-timeout', '3s', '--health-retries', '30']
                entrypoint = cfg.get('Entrypoint') or []
                if entrypoint:
                    argv += ['--entrypoint', entrypoint[0]]
                argv += [image, *entrypoint[1:], *(cfg.get('Cmd') or [])]
                created.append(command('docker', *argv, timeout=60).strip())
            from .broker import _wait_container
            states = []
            for name in created:
                command('docker', 'start', name, timeout=60)
                states.append(_wait_container(name))
            return {'backup_id': backup_id, 'target': self.target, 'verified': True, 'mode': 'isolated_restore',
                    'containers': created, 'volumes': volumes, 'network': network, 'health': states,
                    'completed': all(state.get('health') == 'healthy' for state in states),
                    'overwrites_source': False, 'cleanup': 'Explicit operator removal required; restored data is retained'}
        except BaseException:
            for name in created:
                command('docker', 'rm', '-f', name)
            for volume in volumes:
                command('docker', 'volume', 'rm', volume)
            if network:
                command('docker', 'network', 'rm', network)
            raise
        finally:
            shutil.rmtree(stage, ignore_errors=True)


def execute_backup(operation, arguments, config):
    if set(arguments) - {'target', 'backup_id'}:
        raise DockerBackupError('Unexpected backup arguments')
    manager = DockerBackups(config, arguments.get('target'))
    try:
        if operation == 'docker.backup.create':
            return manager.create()
        if operation == 'docker.backup.list':
            return manager.list()
        if operation == 'docker.backup.verify':
            return manager.verify(arguments.get('backup_id'))
        if operation in {'docker.restore.plan', 'docker.restore.apply'}:
            return manager.restore(arguments.get('backup_id'), apply=operation.endswith('.apply'))
        raise DockerBackupError('Unknown backup operation')
    finally:
        manager.close()
