#!/bin/bash

#### UI

# Prints arguments followed by space, no new line, all in green.
# Does not read input. Use `read` (or `read -s` for secrets).
prompt() {
    echo -e -n "\033[0;32m$*\033[0m "
}

echo_line() {
    print_blue "================================================================================"
}

#### Bash helpers

is_variable_set() {
    set +u
    if [ -z "${!1}" ]; then
        set -u
        return 1
    fi
    set -u
    return 0
}

ensure_variable_set() {
    while [ $# -gt 0 ]; do
        if ! is_variable_set $1; then
            echo "\$$1 was empty or unset.  Aborting."
            exit 1
        fi
        shift
    done
}

#### HSM Helper

check_or_set_dfx_hsm_pin() {
    VALUE=${DFX_HSM_PIN:-}
    if [ -z "$VALUE" ]; then
        prompt "Enter your HSM PIN:"
        read -s DFX_HSM_PIN
        export DFX_HSM_PIN
        echo
    fi
}

#### File interaction helpers

# Cross platform Sha256 file helper
sha_256() {
    if $(which sha256sum >/dev/null); then
        SHA_CMD="sha256sum"
    else
        SHA_CMD="shasum -a 256"
    fi
    $SHA_CMD "$1" | cut -d' ' -f1
}

#### IDL helpers

hex2dec() {
    str=$(echo $@ | awk '{print toupper($0)}')
    echo "ibase=16; $str" | bc
}

# Outputs IDL byte array
hex_to_idl_byte_array() {
    local INPUT=$1

    ARRAY=()
    for x in $(echo $INPUT | fold -w2); do
        ARRAY+=($(hex2dec $x))
    done

    OLDIFS=$IFS
    IFS=";"
    echo "{${ARRAY[*]}}"
    IFS=$OLDIFS
}

#### CI/CD interaction helpers

# TODO deduplicate this from icos_deploy.sh by moving into lib.sh
disk_image_exists() {
    GIT_REVISION=$1
    curl --output /dev/null --silent --head --fail \
        "https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/disk-img-dev/disk-img.tar.zst" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/disk-img.tar.zst"
}

##: latest_commit_with_prebuilt_artifacts
## Gets the latest git commit with a prebuilt governance canister WASM and a disk image
latest_commit_with_prebuilt_artifacts() {

    IC_REPO=$(repo_root)
    pushd "$IC_REPO" >/dev/null

    git fetch origin master
    RECENT_CHANGES=$(git log origin/master -n 100 --pretty=format:'%H')

    for HASH in $RECENT_CHANGES; do
        echo >&2 "Checking $HASH..."
        GZ=$(_download_canister_gz "governance-canister" "$HASH")

        if ungzip "$GZ" >/dev/null 2>&1; then
            echo "$HASH"
            return 0
        fi
    done

    popd >/dev/null

    echo >&2 "None found!"
    return 1
}

#### User interaction helpers
confirm() {
    if [ "${DRY_RUN:-false}" = true ]; then
        print_yellow "(This is just a dry run.)"
    fi

    prompt "Type 'yes' to confirm, anything else, or Ctrl+C to cancel:"
    read CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        echo
        echo "Aborting..."
        exit 1
    fi
}

#### Markdown

filter_out_empty_markdown_sections() {
    # Python is used, because I'm not sure how to do this with sed.
    python3 -c 'import sys, re
s = sys.stdin.read()
print(re.sub(
    r"^(#+) [\w ]+\n+(?=\1 |\Z)",
    "",  # Replace with nothing.
    s,   # Input.
    0,   # Unlimited replacements.
    re.MULTILINE,
)
.strip())'
}

increment_markdown_heading_levels() {
    # Python is used, because I'm not sure how to do this with sed.
    python3 -c 'import sys, re
s = sys.stdin.read()
print(re.sub(
    r"^(#+)",  # Grab Markdown heading.
    r"\1# ",    # Add another # character to increase the level.
    s,   # Input.
    0,   # Unlimited replacements.
    re.MULTILINE,
)
.strip())'
}
