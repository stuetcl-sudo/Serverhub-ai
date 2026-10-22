#!/bin/sh
set -eu
exec /opt/serverhub/recovery/venv/bin/python -m serverhub.ops.release "$@"
