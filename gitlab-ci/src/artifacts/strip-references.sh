#!/bin/bash
#
# Strips references to the nix store. The first argument is the name of the
# artifact to strip. The environment variable "allowedStrippedRefs" is a list
# of space-separated dependencies that may be stripped.
#
# If the artifact contains any reference to the nix store that is not present
# in "allowedStrippedRefs" the script exists with return code 1. The
# "allowedStrippedRefs" may be bash patterns (e.g. `*-crates-io-*`).

set -euo pipefail

artifact=${1:?Must provide an artifact to strip}

log() {
    artifact_name=${artifact_name:-$(basename "$artifact")}
    echo "strip $artifact_name:" "$@"
}

log artifact is "$artifact"

allowedStrippedRefs=${allowedStrippedRefs:-}

allowedRefs=()
log "allowed references:"
if [ -n "$allowedStrippedRefs" ]; then
    for ref in $allowedStrippedRefs; do
        log "  $ref"
        allowedRefs+=("$ref")
    done
fi

log "Stripping $artifact:"
# For each dependency that we found, we iterate through the list of allowed
# dependencies to be stripped. If there we find a match, we strip it, and move
# on to the next dependency. Otherwise (after we iterate over all allowedRef)
# we error out because no match was found.
while IFS= read -r dep; do
    depname=$(basename "$dep")
    for allowedRef in "${allowedRefs[@]}"; do
        # shellcheck disable=SC2254
        case "$dep" in
            $allowedRef)
                log "  /nix/store/$depname"
                sed -i -e "s|/nix/store/$depname-|/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-|g" "$artifact"
                continue 2 # "continues" in the while loop
                ;;
            *) ;;

        esac
    done
    log "Unknown dependency: $dep"
    log "References to $depname aren't allowed to be stripped!"
    exit 1
done < <(
    # here we grab all the mentions of /nix/store but filter out
    # /nix/store/eeeee..., which are placeholder inserted by
    # remove-references-to (the letter 'e' is not allowed in store hashes).
    grep --only-matching -a '/nix/store/[^/]*' "$artifact" \
        | grep -v "/nix/store/e" | sort | uniq \
        || exit 1
)

log "Done stripping $artifact."
