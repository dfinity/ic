#!/bin/bash

# This script adapts the /var/lib/ic/data tree -- since this was "taken
# over" from the previous installation (or be empty after initial install),
# there may be small things that are wrong with it and need adaptation.

set -e

# Fix up ownership -- should be owned by the ic replica service user.
USER=$(stat -c %U /var/lib/ic/data)
if [ "${USER}" != replica ]; then
    chown -R ic-replica /var/lib/ic/data
fi
