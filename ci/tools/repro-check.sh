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
    -h	    this help message
    -p      proposal id to check - the proposal has to be for an Elect Replica proposal
    -c	    git revision/commit to use - the commit has to exist on master branch of
            the IC repository on GitHub
    <empty> no option - uses the commit at the tip of the branch this is run on
USAGE
}

extract_field_json() {
    jq_field="$1"
    input="$2"

    out=$(cat "$input" | jq --raw-output "$jq_field")
    status="$?"

    if [[ "$status" != 0 ]] || [[ "$out" == "null" ]]; then
        error "Field $jq_field does not exist in $input"
    fi

    echo "$out"
}

check_git_repo() {
    log_debug "Check we are inside a Git repository"
    if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]; then
        error "Please run this script inside of a git repository"
    else
        log_debug "Inside git repository"
    fi
}

check_ic_repo() {
    git_remote="$(git config --get remote.origin.url)"

    log_debug "Check the repository is an IC repository"
    # Possible values of `git_remote` are listed below
    # git@gitlab.com:dfinity-lab/public/ic.git
    # git@github.com:dfinity/ic.git
    # https://github.com/dfinity/ic.git
    if [[ "$git_remote" == */ic.git ]] || [[ "$git_remote" == */ic ]]; then
        log_debug "Inside IC repository"
    else
        error "When not specifying any option please run this script inside an IC git repository"
    fi
}

#################### Set-up
if [ "${DEBUG:-}" == "2" ]; then
    set -x
fi

proposal_id=""
git_commit=""
no_option=""
SECONDS=0
pwd="$(pwd)"

# Parse arguments
while getopts ':i:h:c:p:d:' flag; do
    case "${flag}" in
        c) git_commit="${OPTARG}" ;;
        p) proposal_id="${OPTARG}" ;;
        *)
            print_usage
            exit 1
            ;;
    esac
done

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

if [[ "$(cat /proc/meminfo | grep MemTotal | awk '{ print int($2/1024**2) }')" -ge 15 ]]; then
    log_success "More than 16GB of RAM detected"
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

# set the `git_hash` from the `proposal_id` or from the environment
if [ -n "$proposal_id" ]; then
    # format the proposal
    proposal_url="https://ic-api.internetcomputer.org/api/v3/proposals/$proposal_id"
    proposal_body="proposal-body.json"

    log_debug "Fetch the proposal json body"
    proposal_body_status=$(curl --silent --show-error -w %{http_code} --location --retry 5 --retry-delay 10 "$proposal_url" -o "$proposal_body")

    # check for error
    if ! [[ "$proposal_body_status" =~ ^2 ]]; then
        error "Could not fetch $proposal_id, please make sure you have a valid internet connection or that the proposal #$proposal_id exists"
    fi
    log_debug "Extract the package_url"
    proposal_package_url=$(extract_field_json ".payload.release_package_urls[0]" "$proposal_body")

    log_debug "Extract the sha256 sums hex for the artifacts from the proposal"
    proposal_package_sha256_hex=$(extract_field_json ".payload.release_package_sha256_hex" "$proposal_body")

    log_debug "Extract git_hash out of the proposal"
    if grep -q "replica_version_to_elect" "$proposal_body"; then
        guestos_proposal=true
        git_hash=$(extract_field_json ".payload.replica_version_to_elect" "$proposal_body")
    elif grep -q "hostos_version_to_elect" "$proposal_body"; then
        hostos_proposal=true
        git_hash=$(extract_field_json ".payload.hostos_version_to_elect" "$proposal_body")
    else
        error "Proposal #$proposal_id is missing replica_version_to_elect or hostos_version_to_elect"
    fi
else
    log_debug "Extract git_hash from CLI arguments or directory's HEAD"
    git_hash=${git_commit:-$(git rev-parse HEAD)}
fi

tmpdir="$(mktemp -d)"
log "Set our working directory to a temporary one - $tmpdir"

# if we are in debug mode we keep the directories to debug any issues
if [ -z "${DEBUG:-}" ]; then
    trap 'rm -rf "$tmpdir"' EXIT
fi

pushd "$tmpdir"

log "Set and create output directories for the different images"
out="$tmpdir/disk-images/$git_hash"
log "Images will be saved in $out"

ci_out="$out/ci-img"
dev_out="$out/dev-img"
proposal_out="$out/proposal-img"

mkdir -p "$ci_out/guestos" "$ci_out/hostos" "$ci_out/setupos"
mkdir -p "$dev_out/guestos" "$dev_out/hostos" "$dev_out/setupos"
mkdir -p "$proposal_out"

#################### Check Proposal Hash
# download and check the hash matches
if [ -n "$proposal_id" ]; then

    log "Check the proposal url is correctly formatted"
    if [ "${guestos_proposal:-}" == "true" ]; then
        expected_url="https://download.dfinity.systems/ic/$git_hash/guest-os/update-img/update-img.tar.zst"
    else
        expected_url="https://download.dfinity.systems/ic/$git_hash/host-os/update-img/update-img.tar.zst"
    fi

    if [ "$proposal_package_url" != "$expected_url" ]; then
        error "The artifact's URL is wrongly formatted, please report this to DFINITY\n\t\tcurrent  = $proposal_package_url\n\t\texpected = $expected_url"
    fi

    log "Download the proposal artifacts"
    curl --silent --show-error --location --retry 5 --retry-delay 10 \
        --remote-name --output-dir "$proposal_out" "$proposal_package_url"

    pushd "$proposal_out"

    log "Check the hash of the artifacts is the correct one"
    echo "$proposal_package_sha256_hex  update-img.tar.zst" | shasum -a256 -c- >/dev/null

    log_success "The proposal's artifacts and hash match"
    popd
fi

#################### Check CI Hash
download_ci_files() {
    BASE_URL="https://download.dfinity.systems/ic/$git_hash"

    local os_type="$1"
    local output_dir="$2"

    local os_url="${BASE_URL}/${os_type}/update-img/update-img.tar.zst"
    local sha_url="${BASE_URL}/${os_type}/update-img/SHA256SUMS"

    if [ "$os_type" == "host-os" ]; then
        os_url="${BASE_URL}/${os_type}/update-img/update-img.tar.zst"
        sha_url="${BASE_URL}/${os_type}/update-img/SHA256SUMS"
    fi

    if [ "$os_type" == "setup-os" ]; then
        os_url="${BASE_URL}/${os_type}/disk-img/disk-img.tar.zst"
        sha_url="${BASE_URL}/${os_type}/disk-img/SHA256SUMS"
    fi

    log "Download ${os_type^} image built and pushed by CI system..."

    DOWNLOAD_OPTIONS="--silent --show-error --location --retry 5 --retry-delay 10 --remote-name"
    curl $DOWNLOAD_OPTIONS --output-dir "$output_dir" "$os_url"
    curl $DOWNLOAD_OPTIONS --output-dir "$output_dir" "$sha_url"
}

download_ci_files "guest-os" "$ci_out/guestos"
download_ci_files "host-os" "$ci_out/hostos"
download_ci_files "setup-os" "$ci_out/setupos"

check_ci_hash() {
    local os_dir="$1"
    local target_file="$2"
    local output_var="$3"

    pushd "$ci_out/$os_dir"

    # Validate that the computed hash of the target file matches the hash in the SHA256SUMS file
    grep "$target_file" SHA256SUMS | shasum -a256 -c- >/dev/null || error "The hash for $target_file in $os_dir doesn't match the published artifact for git hash: $git_hash"

    # Extract the hash value from the SHA256SUMS file and assign it to the given output variable
    local extracted_hash="$(grep "$target_file" SHA256SUMS | cut -d' ' -f 1)"
    declare -g "$output_var=$extracted_hash"

    popd
}

log "Validating that uploaded image hashes match the provided proposal hashes"

check_ci_hash "guestos" "update-img.tar.zst" "ci_package_guestos_sha256_hex"
check_ci_hash "hostos" "update-img.tar.zst" "ci_package_hostos_sha256_hex"
check_ci_hash "setupos" "disk-img.tar.zst" "ci_package_setupos_sha256_hex"

log_success "The CI's artifacts and hash match"

#################### Verify Proposal Image == CI Image
log "Check the shasum that was set in the proposal matches the one we download from CDN"
if [ -n "$proposal_id" ]; then
    if [ "${guestos_proposal:-}" == "true" ]; then
        if [ "$proposal_package_sha256_hex" != "$ci_package_guestos_sha256_hex" ]; then
            error "The sha256 sum from the proposal does not match the one from the CDN storage for guestOS update-img.tar.zst. The guestos sha256 sum from the proposal: $proposal_package_sha256_hex The guestos sha256 sum from the CDN storage: $ci_package_guestos_sha256_hex."
        else
            log_success "The guestos shasum from the proposal and CDN match"
        fi
    else
        if [ "$proposal_package_sha256_hex" != "$ci_package_hostos_sha256_hex" ]; then
            error "The sha256 sum from the proposal does not match the one from the CDN storage for hostOS update-img.tar.zst. The hostos sha256 sum from the proposal: $proposal_package_sha256_hex The hostos sha256 sum from the CDN storage: $ci_package_hostos_sha256_hex."
        else
            log_success "The guestos shasum from the proposal and CDN match"
        fi

    fi
fi

################### Verify CI Image == Dev Image
pushd "$tmpdir"
# Copy if we are in CI, if there wasn't an option specified or if it was `git_commit`
if [ -n "${CI:-}" ] || [ -n "$no_option" ]; then
    log "Copy IC repository from $pwd to temporary directory"
    git clone "$pwd" ic
else
    log "Clone IC repository"
    git clone https://github.com/dfinity/ic
fi

pushd ic

# Check `git_commit` exists on the master branch of the IC repository on GitHub
if [ -n "$git_commit" ]; then
    check_git_repo
    check_ic_repo

    if ! git cat-file -e "$git_commit^{commit}"; then
        error "When specifying the -c option please specify a git hash which exists as a commit on a branch of the IC repository"
    fi
fi

log "Checkout $git_hash commit"
git fetch --quiet origin "$git_hash"
git checkout --quiet "$git_hash"

log "Build IC-OS"
./ci/container/build-ic.sh --icos
log_success "Built IC-OS successfully"

mv artifacts/icos/guestos/update-img.tar.zst "$dev_out/guestos"
mv artifacts/icos/hostos/update-img.tar.zst "$dev_out/hostos"
mv artifacts/icos/setupos/disk-img.tar.zst "$dev_out/setupos"

compute_dev_hash() {
    local os_dir="$1"
    local local_file="$2"
    local output_var_name="$3"

    pushd "$dev_out/$os_dir"
    local computed_hash="$(shasum -a 256 "$local_file" | cut -d' ' -f1)"
    popd

    declare -g "$output_var_name=$computed_hash"
}

compute_dev_hash "guestos" "update-img.tar.zst" "dev_package_guestos_sha256_hex"
compute_dev_hash "hostos" "update-img.tar.zst" "dev_package_hostos_sha256_hex"
compute_dev_hash "setupos" "disk-img.tar.zst" "dev_package_setupos_sha256_hex"

compare_hashes() {
    local local_hash_var="$1"
    local ci_hash_var="$2"
    local os_type="$3"

    local local_hash_value=${!local_hash_var}
    local ci_hash_value=${!ci_hash_var}

    if [ "$local_hash_value" != "$ci_hash_value" ]; then
        log_stderr "Error! The sha256 sum from the proposal/CDN does not match the one we just built for $os_type. \n\tThe sha256 sum we just built:\t\t$local_hash_value\n\tThe sha256 sum from the CDN: $ci_hash_value."
    else
        log_success "Verification successful for $os_type!"
        log_success "The shasum for $os_type from the artifact built locally and the one fetched from the proposal/CDN match:\n\t\t\t\t\t\tLocal = $local_hash_value\n\t\t\t\t\t\tCDN   = $ci_hash_value\n\n"
    fi
}

log "Check hash of locally built artifact matches the one fetched from the proposal/CDN"

compare_hashes "dev_package_guestos_sha256_hex" "ci_package_guestos_sha256_hex" "GuestOS"
compare_hashes "dev_package_hostos_sha256_hex" "ci_package_hostos_sha256_hex" "HostOS"
compare_hashes "dev_package_setupos_sha256_hex" "ci_package_setupos_sha256_hex" "SetupOS"

log_success "All images are validated successfully"

log "Total time: $(($SECONDS / 3600))h $((($SECONDS / 60) % 60))m $(($SECONDS % 60))s"

exit 0
