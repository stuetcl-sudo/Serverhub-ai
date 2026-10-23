"""Root-installed AppArmor label for the already isolated development runner."""
from pathlib import Path

PROFILE_PATH='/etc/apparmor.d/serverhub-ai-build'
PROFILE='abi <abi/4.0>,\nprofile serverhub-ai-build flags=(unconfined) {\n  userns,\n}\n'


def configure(installer, *, staged=False):
    # This profile is unattached: only our explicit aa-exec invocation uses it.
    # It grants no host UID/capabilities and never disables the kernel restriction.
    if staged or installer.root != Path('/'):
        installer.write(PROFILE_PATH,PROFILE,0o644)
        return {'status':'staged'}
    active=Path('/sys/module/apparmor/parameters/enabled')
    restriction=Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
    if not active.exists() or active.read_text().strip()!='Y' or not restriction.exists() or restriction.read_text().strip()!='1':
        return {'status':'not_required'}
    destination=Path(PROFILE_PATH)
    if destination.exists() and destination.read_text()!=PROFILE:
        from .installer import InstallError
        raise InstallError('Existing serverhub-ai-build AppArmor profile differs; review it explicitly before upgrade')
    installer.write(PROFILE_PATH,PROFILE,0o644)
    installer._run(['/usr/sbin/apparmor_parser','--replace',PROFILE_PATH])
    return {'status':'loaded','profile':'serverhub-ai-build'}
