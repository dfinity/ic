#!/usr/bin/env bash

# Installs needed extensions for the users by default

set -x

installed=$(code --list-extensions | sort)
want_install=$(jq -r '.recommendations[]' .vscode/extensions.json | sort)
to_install=$(comm -13 <(echo "$installed") <(echo "$want_install"))

echo "$to_install" | xargs -I{} code --force --install-extension {}
