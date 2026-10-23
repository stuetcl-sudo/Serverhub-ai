#!/bin/sh
set -eu
exec /opt/serverhub/recovery-ai/venv/bin/python -m serverhub.ops.backup "$@"
