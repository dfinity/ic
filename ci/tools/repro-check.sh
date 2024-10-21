#!/usr/bin/env bash

# This script verifies a specific commit hash or a proposal for reproducibility.
# If it's a proposal, we need to make sure that proposal_hash == CDN_hash == build_hash.
# Otherwise, we only need to make sure that CDN_hash == build_hash.

set -euo pipefail

pushd() {
    command pushd "$@" >/dev/null
}

popd() {
    command popd "$@" >/dev/null
}

print_date() {
    date +'%Y/%m/%d | %H:%M:%S | %s'
}

print_red() {
    echo -e "\033[0;31m$(print_date) $*\033[0m" 1>&2
}

print_green() {
    echo -e "\033[0;32m$(print_date) $*\033[0m"
}

print_yellow() {
    echo -e "\033[0;33m$(print_date) $*\033[0m"
}

print_blue() {
    echo -e "\033[0;34m$(print_date) $*\033[0m"
}

print_purple() {
    echo -e "\033[0;35m$(print_date) $*\033[0m"
}

log() {
    print_blue "[+] $*"
}

log_success() {
    print_green "[+] $*"
}

log_warning() {
    print_yellow "[!] Warning - $*"
}

log_stderr() {
    print_red "[-] $*"
}

log_debug() {
    if [ -n "${DEBUG:-}" ]; then
        print_purple "[_] $*"
    fi
}

error() {
    print_red "[-] $1"
    exit 1
}

print_usage() {
    cat >&2 <<-USAGE
    This script builds and diffs the update image between CI and build-ic
    Pick one of the following options:
    -h        this help message
    --guestos   verify only build reproducibility of GuestOS images
    --hostos    verify only build reproducibility of HostOS images
    --setupos   verify only build reproducibility of SetupOS images
    -p      proposal id to check - the proposal has to be for an Elect Replica proposal
    -c      git revision/commit to use - the commit has to exist on master branch of
            the IC repository on GitHub
    <empty> no option - uses the commit at the tip of the branch this is run on
USAGE
}

#################### Set-up
if [ "${DEBUG:-}" == "2" ]; then
    set -x
fi

# Default: Verify all OS components
verify_guestos="true"
verify_hostos="true"
verify_setupos="true"

proposal_id=""
git_commit=""
no_option=""
SECONDS=0
pwd="$(pwd)"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --guestos) verify_hostos="false"; verify_setupos="false" ;;  # Only verify build reproducibility of GuestOS
        --hostos) verify_guestos="false"; verify_setupos="false" ;;  # Only verify build reproducibility of HostOS
        --setupos) verify_guestos="false"; verify_hostos="false" ;;  # Only verify build reproducibility of SetupOS
        -p) proposal_id="$2"; shift ;;
        -c) git_commit="$2"; shift ;;
        -h) print_usage; exit 0 ;;
        *) print_usage; exit 1 ;;
    esac
    shift
done

# Set default behavior if no flags are provided (i.e., verify all components)
if [ "$OPTIND" -eq 1 ]; then
    verify_guestos="true"
    verify_hostos="true"
    verify_setupos="true"
    no_option="true"
fi

log "Check the environment"
# either of those files should exist
source /usr/lib/os-release 2>/dev/null
source /etc/os-release 2>/dev/null

if [ "$(uname -m)" == "x86_64" ]; then
    log_success "x86_64 architecture detected"
else
    error "Please run this script on x86_64 architecture"
fi

if [ "${NAME:-}" == "Ubuntu" ]; then
    log_success "Ubuntu OS detected"
else
    log_warning "Please run this script on Ubuntu OS"
fi

if [[ $(echo "${VERSION_ID:-} > 22.03" | bc) == 1 ]]; then
    log_success "Version ≥22.04 detected"
else
    log_warning "Please run this script on Ubuntu version 22.04 or higher"
fi

if [[ "$(free -g | awk '/Mem:/ { print $2 }')" -ge 16 ]]; then
    log_success "16GB or more RAM detected"
else
    log_warning "You need at least 16GB of RAM on this machine"
fi

if [[ $(("$(df . --output=avail | tail -n 1)" / 1000000)) -ge 100 ]]; then
    log_success "More than 100GB of free disk space detected"
else
    log_warning "You need at least 100GB of free disk space on this machine"
fi

log "Update package registry"
sudo apt-get update -y
log "Install needed dependencies"
sudo apt-get install git curl jq podman -y

# if no options have been chosen, we assume to check the latest commit of the
# branch we are on.
if [ "$OPTIND" -eq 1 ]; then
    check_git_repo
    check_ic_repo

    no_option="true"
fi

# Download CI artifacts based on selected components
download_ci_files() {
    BASE_URL="https://download.dfinity.systems/ic/$git_hash"

    local os_type="$1"
    local output_dir="$2"

    local os_url="${BASE_URL}/${os_type}/update-img/update-img.tar.zst"
    local sha_url="${BASE_URL}/${os_type}/update-img/SHA256SUMS"

    if [ "$os_type" == "setup-os" ]; then
        os_url="${BASE_URL}/${os_type}/disk-img/disk-img.tar.zst"
        sha_url="${BASE_URL}/${os_type}/disk-img/SHA256SUMS"
    fi

    log "Download ${os_type^} image built and pushed by CI system..."

    DOWNLOAD_OPTIONS="--silent --show-error --location --retry 5 --retry-delay 10 --remote-name"
    curl $DOWNLOAD_OPTIONS --output-dir "$output_dir" "$os_url"
    curl $DOWNLOAD_OPTIONS --output-dir "$output_dir" "$sha_url"
}

# Download the requested OS images
if [ "$verify_guestos" == "true" ]; then
    download_ci_files "guest-os" "$ci_out/guestos"
fi
if [ "$verify_hostos" == "true" ]; then
    download_ci_files "host-os" "$ci_out/hostos"
fi
if [ "$verify_setupos" == "true" ]; then
    download_ci_files "setup-os" "$ci_out/setupos"
fi

# Check hashes, verify based on the flags
check_ci_hash() {
    local os_dir="$1"
    local target_file="$2"
    local output_var="$3"

    pushd "$ci_out/$os_dir"

    grep "$target_file" SHA256SUMS | shasum -a256 -c- >/dev/null || error "The hash for $target_file in $os_dir doesn't match the published artifact for git hash: $git_hash"

    local extracted_hash="$(grep "$target_file" SHA256SUMS | cut -d' ' -f 1)"
    declare -g "$output_var=$extracted_hash"

    popd
}

log "Validating that uploaded image hashes match the provided proposal hashes"

if [ "$verify_guestos" == "true" ]; then
    check_ci_hash "guestos" "update-img.tar.zst" "ci_package_guestos_sha256_hex"
fi
if [ "$verify_hostos" == "true" ]; then
    check_ci_hash "hostos" "update-img.tar.zst" "ci_package_hostos_sha256_hex"
fi
if [ "$verify_setupos" == "true" ]; then
    check_ci_hash "setupos" "disk-img.tar.zst" "ci_package_setupos_sha256_hex"
fi

log_success "The CI's artifacts and hash match"
