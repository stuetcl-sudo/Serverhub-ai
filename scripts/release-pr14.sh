#!/bin/bash
# Reviewed offline owner maintenance only. Never called by an AI worker.
set -euo pipefail
if [[ ${EUID} -ne 0 || $# -ne 0 ]]; then
  echo 'Run exactly: sudo bash scripts/release-pr14.sh' >&2
  exit 1
fi
release_script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
cd /
# Filled from the reviewed helper bytes; never execute a later checkout reread.
release_helper_sha=ff0192e4f85a958cd172699ac1aa3d7c81fd0a42673f033dd18abdf65fc82ed1
release_bootstrap_dir=$(/usr/bin/mktemp -d /run/serverhub-pr14.XXXXXXXX)
trap '/usr/bin/rm -f -- "$release_bootstrap_dir/release_pr14.py"; /usr/bin/rmdir -- "$release_bootstrap_dir"' EXIT
/usr/bin/install -m 0600 -- "$release_script_dir/release_pr14.py" "$release_bootstrap_dir/release_pr14.py"
release_actual_sha=$(/usr/bin/sha256sum -- "$release_bootstrap_dir/release_pr14.py")
if [[ ${release_actual_sha%% *} != "$release_helper_sha" ]]; then
  echo 'Reviewed release helper hash mismatch; nothing was activated.' >&2
  exit 1
fi
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  /opt/serverhub/recovery-ai/venv/bin/python -I \
  "$release_bootstrap_dir/release_pr14.py"
