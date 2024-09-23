#!/usr/bin/env bash

# Tear-down and re-deploy the IC using Ansible.
#
# This script takes one positional argument:
#   <deployment_identifier>: The deployment referenced in `/testnet/env/${deployment}`
#
# Before running for the first time, make sure you have all the dependencies:
# sudo apt install ansible jq rclone

set -eEuo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel)"
find "$REPO_ROOT/testnet" -type d -exec chmod 0775 '{}' \;

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

if [[ "${BASH_VERSINFO:-0}" -lt 4 ]]; then
    err "Bash 4+ is required"
    exit 1
fi

function exit_usage() {
    if (($# < 1)); then
        err 'Usage: icos_deploy.sh [--git-head ] [--git-revision <git_revision>] [--dkg-interval-length <dil>] [--max-ingress-bytes-per-message <dil>] [--ansible-args <additional-args>] [--hosts-ini <hosts_override.ini>] [--no-boundary-nodes] <deployment_name>'
        err '    --git-head                            Deploy the testnet from the current git head.'
        err '    --git-revision <git_revision>         Deploy the testnet from the given git revision.'
        err '    --ansible-args <additional-args>      Additional ansible args. Can be specified multiple times.'
        err '    --dkg-interval-length <dil>           Set DKG interval length (-1 if not provided explicitly, which means - default will be used)'
        err '    --max-ingress-bytes-per-message <dil> Set maximum ingress size in bytes (-1 if not provided explicitly, which means - default will be used)'
        err '    --hosts-ini <hosts_override.ini>      Override the default ansible hosts.ini to set different testnet configuration'
        err '    --no-api-nodes                        Do not deploy API boundary nodes even if they are declared in the hosts.ini file'
        err '    --no-boundary-nodes                   Do not deploy boundary nodes even if they are declared in the hosts.ini file'
        err '    --boundary-dev-image		           Use development image of the boundary node VM'
        err '    --with-testnet-keys                   Initialize the registry with readonly and backup keys from testnet/config/ssh_authorized_keys'
        err '    --allow-specified-ids                 Allow installing canisters at specified IDs'
        err ''
        err 'To get the latest branch revision that has a disk image pre-built, you can use ci/src/artifacts/newest_sha_with_disk_image.sh'
        err 'Example (deploy latest master to small-a):'
        err ''
        err '    testnet/tools/icos_deploy.sh small-a --git-revision $(ci/src/artifacts/newest_sha_with_disk_image.sh master)'
        err ''
        exit 1
    fi
}

function ansible() {
    ansible-playbook ${ANSIBLE_ARGS[@]} "$@"
}

# Helper function to convert times
function dateFromEpoch() {
    if [[ "$(uname)" == "Darwin" ]]; then
        date -j -f '%s' "$1"
    else
        date --date="@$1"
    fi
}

function disk_image_exists() {
    curl --output /dev/null --silent --head --fail \
        "https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/disk-img-dev/disk-img.tar.zst" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/disk-img.tar.zst"
}

ANSIBLE_ARGS=()
HOSTS_INI_FILENAME="${HOSTS_INI_FILENAME:-hosts.ini}"

if [ -n "${ANSIBLE_REMOTE_USER:-}" ]; then
    ANSIBLE_ARGS+=(-u $ANSIBLE_REMOTE_USER)
fi

while [ $# -gt 0 ]; do
    case "${1}" in
        --git-head)
            GIT_REVISION="$(git rev-parse --verify HEAD)"
            ;;
        -s | --git-revision)
            GIT_REVISION="${2:-}"
            if [[ -z "${GIT_REVISION}" ]]; then exit_usage; fi
            shift
            ;;
        --ansible-args)
            if [[ -z "${2:-}" ]]; then exit_usage; fi
            ANSIBLE_ARGS+=($2)
            shift
            ;;
        --dkg-interval-length)
            DKG_INTERVAL_LENGTH="${2:-}"
            if [[ -z "${DKG_INTERVAL_LENGTH}" ]]; then exit_usage; fi
            shift
            ;;
        --max-ingress-bytes-per-message)
            MAX_INGRESS_BYTES_PER_MESSAGE="${2:-}"
            if [[ -z "${MAX_INGRESS_BYTES_PER_MESSAGE}" ]]; then exit_usage; fi
            shift
            ;;
        --hosts-ini)
            if [[ -z "${2:-}" ]]; then exit_usage; fi
            HOSTS_INI_FILENAME="${2}"
            shift
            ;;
        --boundary-dev-image)
            BOUNDARY_IMAGE_TYPE="-dev"
            ;;
        --no-api-nodes)
            USE_API_NODES="false"
            ;;
        --no-boundary-nodes)
            USE_BOUNDARY_NODES="false"
            ;;
        --with-testnet-keys)
            WITH_TESTNET_KEYS="--with-testnet-keys"
            ;;
        --allow-specified-ids)
            ALLOW_SPECIFIED_IDS="--allow-specified-ids"
            ;;
        -?*) exit_usage ;;
        *) deployment="$1" ;;
    esac
    shift
done

if [[ -z "${GIT_REVISION:-}" ]]; then
    echo "ERROR: GIT_REVISION not set."
    echo "Please provide the GIT_REVISION as env. variable or the command line with --git-revision <value>"
    exit_usage
fi

if [[ -z "${deployment:-}" ]]; then
    echo "ERROR: No deployment specified."
    exit_usage
fi

# Negative DKG value means unset (default will be used)
DKG_INTERVAL_LENGTH="${DKG_INTERVAL_LENGTH:=-1}"
# Negative value means unset (default will be used)
MAX_INGRESS_BYTES_PER_MESSAGE="${MAX_INGRESS_BYTES_PER_MESSAGE:=-1}"
# This environment variable will be picked up by the Ansible inventory generation script.
# No further action is required to use the custom HOSTS_INI file.
export HOSTS_INI_FILENAME
hosts_ini_file_path="${REPO_ROOT}/testnet/env/${deployment}/${HOSTS_INI_FILENAME}"
if [[ ! -f ${hosts_ini_file_path} ]]; then
    echo >&2 "The Ansible inventory file does not exist, aborting: ${hosts_ini_file_path}"
    exit 1
fi

for i in {1..60}; do
    if disk_image_exists; then
        echo "Disk image found for ${GIT_REVISION}"
        break
    fi
    echo "Disk image not available for ${GIT_REVISION}, waiting 30s for it to be built by the CI ($i/60)"
    sleep 30
done
if [[ $i -ge 60 ]]; then
    echo "Disk image not found for ${GIT_REVISION}, giving up"
    exit 1
fi

echo "Deploying to ${deployment} from git revision ${GIT_REVISION}"

starttime="$(date '+%s')"
echo "**** Deployment start time: $(dateFromEpoch "${starttime}")"

if command -v ip &>/dev/null; then
    ipv4_info="$(ip -4 address show | grep -vE 'valid_lft')"
    ipv6_info="$(ip -6 address show | grep -vE 'valid_lft|fe80::')"

    echo "-------------------------------------------------------------------------------
    **** Local IPv4 address information:

    ${ipv4_info}

    -------------------------------------------------------------------------------
    **** Local IPv6 address information:

    ${ipv6_info}

    -------------------------------------------------------------------------------"
fi

MEDIA_PATH="${REPO_ROOT}/artifacts/guestos/${deployment}/${GIT_REVISION}"
BN_MEDIA_PATH="${REPO_ROOT}/artifacts/boundary-guestos/${deployment}/${GIT_REVISION}"
INVENTORY="${REPO_ROOT}/testnet/env/${deployment}/hosts"
USE_API_NODES="${USE_API_NODES:-true}"
USE_BOUNDARY_NODES="${USE_BOUNDARY_NODES:-true}"

rm -rf "${BN_MEDIA_PATH}"
mkdir -p "${BN_MEDIA_PATH}"
"${INVENTORY}" --list >"${BN_MEDIA_PATH}/list.json"

# Check if hosts.ini has boundary nodes
if jq <"${BN_MEDIA_PATH}/list.json" -e '.boundary.hosts | length == 0' >/dev/null; then
    USE_BOUNDARY_NODES="false"
fi
if jq <"${BN_MEDIA_PATH}/list.json" -e '.api.hosts | length == 0' >/dev/null; then
    USE_API_NODES="false"
fi

if [[ "${USE_BOUNDARY_NODES}" == "true" ]]; then
    ANSIBLE_ARGS+=("-e" "bn_media_path=${BN_MEDIA_PATH}")
else
    ANSIBLE_ARGS+=("--skip-tags" "boundary_node_vm")
fi

if [[ "${USE_API_NODES}" == "true" ]]; then
    ANSIBLE_ARGS+=("-e" "api_media_path=${API_MEDIA_PATH}")
else
    ANSIBLE_ARGS+=("--skip-tags" "api_node_vm")
fi

if ! [[ -z "${ALLOW_SPECIFIED_IDS+x}" ]]; then
    ANSIBLE_ARGS+=("-e" "allow_specified_ids=true")
fi

ANSIBLE_ARGS+=(
    "-i" "${INVENTORY}"
    "-e" "bn_image_type=${BOUNDARY_IMAGE_TYPE:-}"
    "-e" "ic_git_revision=${GIT_REVISION}"
    "-e" "ic_media_path=${MEDIA_PATH}"
    "-e" "ic_boundary_node_image=boundary"
)

# Ensure we kill these on CTRL+C or failure
trap 'echo "EXIT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' EXIT

TMPDIR=$(mktemp -d /tmp/icos-deploy.sh.XXXXXX)

DESTROY_OUT="${TMPDIR}/destroy.log"
echo "**** Start destroying old deployment (log ${DESTROY_OUT})"
COMMAND=$(
    cat <<EOF
set -x;
$(declare -f ansible)
$(declare -p ANSIBLE_ARGS)

cd "${REPO_ROOT}/testnet/ansible"
ansible icos_network_redeploy.yml -e ic_state=destroy
EOF
)
echo "${COMMAND}"
SHELL="${BASH}" script --quiet --return "${DESTROY_OUT}" --command "${COMMAND}" >/dev/null 2>&1 &
DESTROY_PID=$!

echo "-------------------------------------------------------------------------------"

echo "**** Build USB sticks for IC nodes - ($(dateFromEpoch "$(date '+%s')"))"
rm -rf "${MEDIA_PATH}"
mkdir -p "${MEDIA_PATH}"
"${INVENTORY}" --media-json >"${MEDIA_PATH}/${deployment}.json"

"${REPO_ROOT}/testnet/tools/build-guestos-configs.sh" \
    --debug \
    --input="${MEDIA_PATH}/${deployment}.json" \
    --output="${MEDIA_PATH}" \
    --git-revision="${GIT_REVISION}" \
    --whitelist="${REPO_ROOT}/testnet/env/${deployment}/provisional_whitelist.json" \
    --dkg-interval-length=${DKG_INTERVAL_LENGTH} \
    --max-ingress-bytes-per-message=${MAX_INGRESS_BYTES_PER_MESSAGE} \
    --output-nns-public-key="${MEDIA_PATH}/nns-public-key.pem" \
    ${WITH_TESTNET_KEYS:-} \
    ${ALLOW_SPECIFIED_IDS:-}

SCP_PREFIX=""
NNS_PUBLIC_KEY=$(sed '1d;$d' "${MEDIA_PATH}/nns-public-key.pem" | tr -d '\n\r')
if [ -n "${ANSIBLE_REMOTE_USER:-}" ]; then
    SCP_PREFIX="${ANSIBLE_REMOTE_USER}@"
fi

if [[ "${USE_BOUNDARY_NODES}" == "true" ]]; then
    BOUNDARY_OUT="${TMPDIR}/build-boundary.log"
    echo "**** Build USB sticks for boundary nodes - ($(dateFromEpoch "$(date '+%s')"))"
    COMMAND=$(
        cat <<EOF
set -x
$(declare -f err)

HOSTS=($(jq <"${BN_MEDIA_PATH}/list.json" -r '(.physical_hosts.hosts // [])[]'))
CERT_NAME=$(jq <"${BN_MEDIA_PATH}/list.json" -r '.boundary.vars.cert_name // empty')

echo "**** Trying to SCP using $(whoami)"

mkdir "${BN_MEDIA_PATH}/certs"
if [[ -z \${CERT_NAME+x} ]]; then
    err "'.boundary.vars.cert_name' was not defined"
else
    # succeed if at least one of the hosts has the necessary certificates
    SUCCESS=0
    for HOST in "\${HOSTS[@]}"; do
        echo >&2 "\$(date --rfc-3339=seconds): Copying \$CERT_NAME from server \$HOST"
        if scp -B -o "ConnectTimeout 30" -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -r "${SCP_PREFIX}\${HOST}:/etc/letsencrypt/live/\${CERT_NAME}/*" "${BN_MEDIA_PATH}/certs/"; then
            SUCCESS=1
            break
        fi
    done

    if [[ \${SUCCESS} -eq 0 ]]; then
        err "failed to find certificate \${CERT_NAME} on any designated server"
        exit 1
    fi
fi

echo >&2 "$(date --rfc-3339=seconds): Running build-deployment.sh"

"${REPO_ROOT}"/ic-os/boundary-guestos/scripts/build-deployment.sh \
    --env=test \
    --input="${MEDIA_PATH}/${deployment}.json" \
    --output="${BN_MEDIA_PATH}" \
    --certdir="${BN_MEDIA_PATH}/certs" \
    --nns_public_key="${MEDIA_PATH}/nns-public-key.pem"
EOF
    )
    echo ${COMMAND}
    SHELL="${BASH}" script --quiet --return "${BOUNDARY_OUT}" --command "${COMMAND}" >/dev/null 2>&1 &
    BOUNDARY_PID=$!
fi

echo "-------------------------------------------------------------------------------"

# In case someone wants to deploy with a locally built disk image the following lines contain
# the necessary commands.

# echo "**** Remove previous disk image"
# rm -f ${HOME}/disk.*

# echo "**** Build disk image"
# bazel build //ic-os/guestos/envs/dev/...
# cp bazel-bin/ic-os/guestos/envs/dev/disk.img "${MEDIA_PATH}/disk.img"

# Wait on the destroy to finish
echo "**** Finishing destroy - ($(dateFromEpoch "$(date '+%s')"))"
DESTROY_STATUS=0
wait ${DESTROY_PID} || DESTROY_STATUS=1
cat "${DESTROY_OUT}" || true
if [[ ${DESTROY_STATUS} -ne 0 ]]; then
    exit $(tail -1 "${DESTROY_OUT}" | sed -re "s/.*=\"([0-9]+).*/\1/")
fi

# Wait on the boundary node image to finish
if [[ "${USE_BOUNDARY_NODES}" == "true" ]]; then
    echo "**** Finishing boundary image - ($(dateFromEpoch "$(date '+%s')")) (${BOUNDARY_OUT})"
    BOUNDARY_STATUS=0
    wait ${BOUNDARY_PID} || BOUNDARY_STATUS=1
    cat "${BOUNDARY_OUT}" || true
    if [[ ${BOUNDARY_STATUS} -ne 0 ]]; then
        exit $(tail -1 "${BOUNDARY_OUT}" | sed -re "s/.*=\"([0-9]+).*/\1/")
    fi

    DOMAIN=$(jq <"${MEDIA_PATH}/${deployment}.json" -r '.bn_vars.domain // empty')
fi

# Wait on the api node image to finish
if [[ "${USE_API_NODES}" == "true" ]]; then
    echo "**** Finishing api image - ($(dateFromEpoch "$(date '+%s')"))"
    API_STATUS=0
    wait ${API_PID} || API_STATUS=1
    cat "${API_OUT}" || true
    if [[ ${API_STATUS} -ne 0 ]]; then
        exit $(tail -1 "${API_OUT}" | sed -re "s/.*=\"([0-9]+).*/\1/")
    fi
fi

rm -rf "${TMPDIR}"
echo "-------------------------------------------------------------------------------"
cd "${REPO_ROOT}/testnet/ansible"

echo "**** Remove eventual monitoring - ($(dateFromEpoch "$(date '+%s')"))"
ansible ic_p8s_service_discovery_destroy.yml

echo "**** Create new IC instance - ($(dateFromEpoch "$(date '+%s')"))"
ansible icos_network_redeploy.yml -e ic_state="create"

echo "**** Start VMs - ($(dateFromEpoch "$(date '+%s')"))"
ansible icos_network_redeploy.yml -e ic_state="start"

echo "**** Install NNS canisters - ($(dateFromEpoch "$(date '+%s')"))"
ansible icos_network_redeploy.yml -e ic_state="install"

echo "**** Start monitoring - ($(dateFromEpoch "$(date '+%s')"))"
ansible ic_p8s_service_discovery_install.yml -e nns_public_key="${NNS_PUBLIC_KEY}"

endtime="$(date '+%s')"
echo "**** Completed deployment at $(dateFromEpoch "${endtime}") (start time was $(dateFromEpoch "${starttime}"))"
if [[ -n "${DOMAIN:-}" ]]; then
    echo "Access through 'https://${DOMAIN}'"
fi
duration=$((endtime - starttime))
echo "**** $((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

trap - EXIT
