#!/bin/sh
set -eu
SERVERHUB_SOURCE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$SERVERHUB_SOURCE/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m serverhub.ops.installer --source "$SERVERHUB_SOURCE" "$@"
