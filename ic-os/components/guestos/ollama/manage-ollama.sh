#!/bin/bash
set -e

# Transparently switch uid to root in order to perform the privileged function.
# SELinux restrictions and standard permissions still apply, the script and
# the calling user are restricted to being allowed to sudo only this.
if [ $(id -u) != 0 ]; then
    exec sudo "$0" "$@"
fi

ACTION="$1"

# All three units (the cert generator, the TLS terminator, and ollama itself)
# are disabled by default in the GuestOS image because regular (non-AI) nodes
# don't need them and a failed cert generation would surface as a "failed
# unit" in monitoring. The orchestrator's `AiNodeManager` calls this script
# whenever the local `AiNodeRecord` flips, so non-AI nodes never bring any
# of this up.
case "$ACTION" in
    start)
        # Cert must exist before stunnel starts; service is `Type=oneshot`
        # with `RemainAfterExit=yes`, so `start` is idempotent.
        /bin/systemctl start generate-ollama-tls-cert.service
        /bin/systemctl start ollama-tls.service
        /bin/systemctl start ollama.service
        ;;
    stop)
        # Stop in reverse order. The cert generator is `RemainAfterExit=yes`
        # and has nothing to tear down; leave it active so the cert remains
        # valid for the next start.
        /bin/systemctl stop ollama.service
        /bin/systemctl stop ollama-tls.service
        ;;
    *)
        echo "Usage: $0 {start|stop}" >&2
        exit 2
        ;;
esac
