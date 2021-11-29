#!/bin/bash
#
# Relocates all darwin system libraries to /usr/lib.
#
# This rewrites the mach-o header to point to /usr/lib for all libraries,
# instead of pointing to the Nix store.

set -euo pipefail

artifact=${1:?Must provide an artifact for syslib relocation}

log() {
    artifact_name=${artifact_name:-$(basename "$artifact")}
    echo "relocate-darwin-syslibs $artifact_name:" "$@"
}

# The list of libraries that we allow for relocation. The list should only
# contain system libraries, e.g. not "libssl" or similar. Non-system libraries
# should be statically linked.
#
# On macOS Big Sur and later these libraries don't exist on the filesystem anymore, but are
# automatically looked up by dyld. As a result you can't verify that a reference is
# valid just by checking for the existence of /usr/lib/libSystem.B.dylib for example,
# and you need to run the resulting binary to double-check. (Although you should be
# doing that anyway.)
allowedSystemLibs=(
    "libSystem*.dylib"
    "libresolv*.dylib"
    "libc++*.dylib"
    "libtapi.dylib"
    "libiconv.dylib"
)

chmod +w "$artifact"

# For all dynamic dependencies, grab their path with otool. If they're in the
# Nix store, rewrite the entries to point to /usr/lib.
log "Relocating libraries of $artifact:"
while IFS= read -r lib; do
    libname=$(basename "$lib")

    if [[ $lib == "$artifact" ]]; then continue; fi

    for allowedLib in "${allowedSystemLibs[@]}"; do
        # shellcheck disable=SC2254
        case "$libname" in
            $allowedLib)
                newlibname=/usr/lib/''${libname%%\.*}.''${libname##*\.}
                log "    $lib -> $newlibname"
                install_name_tool -change "$lib" "$newlibname" "$artifact"
                continue 2 # "continues" in the while loop
                ;;
            *) ;;

        esac
    done

    log "Unknown library: '$lib'"
    log "Library $lib isn't allowed to be relocated!"
    exit 1
done < <(
    otool -L "$artifact" \
        | grep --only-match '/nix/store/[a-zA-Z0-9.+-/]*'
)

log "$(basename "$artifact") was patched:"
otool -L "$artifact"
