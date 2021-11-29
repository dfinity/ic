#!@shell@
. @utils@
exename=@exename@
exepath="@rustc@/bin/$exename"
isBuildScript=
outputName=
isTest=
args=("$@")
for i in "${!args[@]}"; do
    if [[ "${args[$i]}" = metadata=* ]]; then
        if [ -z "$IN_NIX_SHELL" ]; then
            args[$i]="metadata=$NIX_RUST_METADATA"
        fi
    elif [ "${args[$i]}" = "--crate-name" ]; then
        if [[ "${args[$i + 1]}" = build_script_* ]]; then
            isBuildScript=1
        else
            outputName="${args[$i + 1]}"
        fi
    elif [ "${args[$i]}" = "--test" -o "${args[$i]} ${args[$i + 1]}" = "--cfg test" ]; then
        isTest=1
    elif [[ -n "$selfLib" && -n "$isTest" && "${args[$i]}" = "--extern" && "${args[$i + 1]}" = "$crateName="* ]]; then
        args[$(expr $i + 1)]="$crateName=$selfLib/lib$crateName.rlib"
    fi
done
if [ "$isBuildScript" ]; then
    args+=($NIX_RUST_BUILD_LINK_FLAGS)
else
    args+=($NIX_RUST_LINK_FLAGS)
fi
if [ "$exename" = rustc ]; then
    # not supported by rustdoc, which is called to run doctests
    args+=("--remap-path-prefix" "$NIX_BUILD_TOP=/source")

    crate_custom_args_name="RUSTC_USE_CUSTOM_ARGS_$outputName"
    if echo "$RUSTC_CUSTOM_ARGS_BINARIES" | sed -e 's/-/_/g' | grep -q "\\b$outputName\\b"; then
        # Add custom args if it is listed in RUSTC_CUSTOM_ARGS_CRATES (used by nix-shell only)
        args+=($RUSTC_CUSTOM_ARGS)
    elif [ "$(eval 'echo $'$crate_custom_args_name)" = "1" ]; then
        # Or if we have a custom setting matching outputName
        args+=($RUSTC_CUSTOM_ARGS)
    elif [ -n "$isTest" ]; then
        # Or when it is a test
        args+=($RUSTC_CUSTOM_ARGS)
    fi
fi
if ((NIX_DEBUG >= 1)); then
    echo >&2 "$exepath ${args[@]}"
fi
exec "$exepath" "${args[@]}"
