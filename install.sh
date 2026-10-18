#!/bin/sh
# Native Ubuntu/Debian systemd installer. Never downloads or executes a shell script.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$HERE/scripts/install.py" "$@"
