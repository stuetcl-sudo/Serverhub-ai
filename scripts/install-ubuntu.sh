#!/bin/bash
# Single native workflow. Build as the invoking user, apply privileged steps only through sudo.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
if [[ $(id -u) == 0 ]]; then
  echo 'Run as your normal Ubuntu user with sudo access; source builds must not run as root.' >&2
  exit 1
fi
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 && $(uname -m) == x86_64 ]] || { echo 'Requires Ubuntu 24.04 x86_64' >&2; exit 1; }
SERVERHUB_BUILD_ONLY=false
if [[ "${1:-}" == --build-only ]]; then SERVERHUB_BUILD_ONLY=true; shift; fi
python3.12 -c 'import sys; assert sys.version_info >= (3,12)'
if [[ "$SERVERHUB_BUILD_ONLY" != true ]]; then
  sudo env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" python3.12 -B -m serverhub.ops.installer --source "$PWD" --preflight
fi
sudo apt-get update
sudo apt-get install -y --no-install-recommends python3-venv python3-pip postgresql-16 postgresql-client-16 ca-certificates iproute2 procps util-linux curl xz-utils bubblewrap git apparmor
# Official Node binary, pinned to an upstream security release and SHA256.
# Installed only inside this checkout, without replacing any system Node.
SERVERHUB_NODE_VERSION=22.23.4
SERVERHUB_NODE_ARCHIVE="node-v${SERVERHUB_NODE_VERSION}-linux-x64.tar.xz"
mkdir -p .build-tools
if [[ ! -x ".build-tools/node-v${SERVERHUB_NODE_VERSION}-linux-x64/bin/node" ]]; then
  curl --fail --location --proto '=https' --tlsv1.2 "https://nodejs.org/dist/v${SERVERHUB_NODE_VERSION}/${SERVERHUB_NODE_ARCHIVE}" --output ".build-tools/$SERVERHUB_NODE_ARCHIVE"
  (cd .build-tools && echo "1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce  $SERVERHUB_NODE_ARCHIVE" | sha256sum --check)
  tar -xJf ".build-tools/$SERVERHUB_NODE_ARCHIVE" -C .build-tools
fi
export PATH="$PWD/.build-tools/node-v${SERVERHUB_NODE_VERSION}-linux-x64/bin:$PATH"
python3.12 -m venv .build-venv
.build-venv/bin/python -m pip install --require-hashes -r requirements.lock
.build-venv/bin/python -m pip install 'build==1.6.1' 'hatchling==1.27.0'
(cd frontend && npm ci && npm run build)
# Avoid accumulating multiple application wheels across reruns.
mkdir -p dist
rm -f dist/serverhub_ai_os-*.whl dist/serverhub_ai_os-*.tar.gz
.build-venv/bin/python -m build
if [[ "$SERVERHUB_BUILD_ONLY" == true ]]; then exit 0; fi
sudo env PYTHONPATH="$PWD/src" "$PWD/.build-venv/bin/python" -m serverhub.ops.installer --source "$PWD" --apply --install-dependencies "$@"
