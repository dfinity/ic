#!/bin/bash
set -e

# Transparently switch uid to root in order to perform the privileged function.
# SELinux restrictions and standard permissions still apply, the script and
# the calling user are restricted to being allowed to sudo only this.
if [ $(id -u) != 0 ]; then
    exec sudo "$0" "$@"
fi

ACTION="$1"

case "$ACTION" in
    start)
        /bin/systemctl start ollama.service
        ;;
    stop)
        /bin/systemctl stop ollama.service
        ;;
    *)
        echo "Usage: $0 {start|stop}" >&2
        exit 2
        ;;
esac
