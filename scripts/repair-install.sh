#!/bin/sh
# Explicit local-root trust-boundary upgrade after reviewing/building this checkout.
set -eu
SERVERHUB_SOURCE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$SERVERHUB_SOURCE/src"
SERVERHUB_PYTHON="$SERVERHUB_SOURCE/.build-venv/bin/python"
if [ ! -x "$SERVERHUB_PYTHON" ]; then
  SERVERHUB_PYTHON=/opt/serverhub/current/venv/bin/python
fi
exec "$SERVERHUB_PYTHON" -m serverhub.ops.repair --source "$SERVERHUB_SOURCE" "$@"
