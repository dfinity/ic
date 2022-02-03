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

function exit_usage() {
    if (($# < 1)); then
        echo >&2 "Usage: icos_deploy.sh [--git-head ] [--git-revision <git_revision>] [--dkg-interval-length <dil>] [--max-ingress-bytes-per-message <dil>] [--ansible-args <additional-args>] [--hosts-ini <hosts_override.ini>] [--no-boundary-nodes] [--icos-boundary-nodes] <deployment_name>"
        echo >&2 "    --git-head                            Deploy the testnet from the current git head."
        echo >&2 "    --git-revision <git_revision>         Deploy the testnet from the given git revision."
        echo >&2 "    --ansible-args <additional-args>      Additional ansible args. Can be specified multiple times."
        echo >&2 "    --dkg-interval-length <dil>           Set DKG interval length (-1 if not provided explicitly, which means - default will be used)"
        echo >&2 "    --max-ingress-bytes-per-message <dil> Set maximum ingress size in bytes (-1 if not provided explicitly, which means - default will be used)"
        echo >&2 "    --hosts-ini <hosts_override.ini>      Override the default ansible hosts.ini to set different testnet configuration"
        echo >&2 "    --no-boundary-nodes                   Do not deploy boundary nodes even if they are declared in the hosts.ini file"
        echo >&2 "    --icos-boundary-nodes                 Launch boundary nodes as self-contained VMs (performs local build)"
        echo >&2 "    --with-testnet-keys                   Initialize the registry with readonly and backup keys from testnet/config/ssh_authorized_keys"
        echo >&2 -e "\nTo get the latest branch revision that has a disk image pre-built, you can use gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh"
        echo >&2 -e "Example (deploy latest master to small-a):\n"

        echo >&2 -e "    testnet/tools/icos_deploy.sh small-a --git-revision \$(gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh master)\n"
        exit 1
    fi
}

deployment=""
GIT_REVISION="${GIT_REVISION:-}"
ANSIBLE_ARGS=()
HOSTS_INI_FILENAME="${HOSTS_INI_FILENAME:-hosts.ini}"
USE_BOUNDARY_NODES="true"
USE_ICOS_BOUNDARY_NODE_VMs="false"
WITH_TESTNET_KEYS=""

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
        --no-boundary-nodes)
            USE_BOUNDARY_NODES="false"
            ;;
        --icos-boundary-nodes)
            # This is a temporay switch to integrated the upcoming self-contained boundary node VM
            USE_ICOS_BOUNDARY_NODE_VMs="true"
            ;;
        --with-testnet-keys)
            WITH_TESTNET_KEYS="--with-testnet-keys"
            ;;
        -?*) exit_usage ;;
        *) deployment="$1" ;;
    esac
    shift
done

if [[ -z "$GIT_REVISION" ]]; then
    echo "ERROR: GIT_REVISION not set."
    echo "Please provide the GIT_REVISION as env. variable or the command line with --git-revision <value>"
    exit_usage
fi

if [[ -z "$deployment" ]]; then
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
hosts_ini_file_path="$REPO_ROOT/testnet/env/$deployment/$HOSTS_INI_FILENAME"
if [[ ! -f $hosts_ini_file_path ]]; then
    echo >&2 "The Ansible inventory file does not exist, aborting: $hosts_ini_file_path"
    exit 1
fi

function disk_image_exists() {
    curl --output /dev/null --silent --head --fail \
        "https://download.dfinity.systems/ic/$GIT_REVISION/guest-os/disk-img/disk-img.tar.gz" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/$GIT_REVISION/guest-os/disk-img.tar.gz"
}

for i in {1..60}; do
    if disk_image_exists; then
        echo "Disk image found for $GIT_REVISION"
        break
    fi
    echo "Disk image not available for $GIT_REVISION, waiting 30s for it to be built by the CI ($i/60)"
    sleep 30
done
if [[ $i -ge 60 ]]; then
    echo "Disk image not found for $GIT_REVISION, giving up"
    exit 1
fi

echo "Deploying to $deployment from git revision $GIT_REVISION"

# Helper function to convert times
dateFromEpoch() {
    date --date="@$1"
}

boundary_nodes_exists() {
    INVENTORY="$1"
    GRPS=$(ansible-inventory -i "$INVENTORY" --list | jq -c -r ".nodes.children|.[]")
    grep -Fxq "boundary" <<<$GRPS
}

starttime="$(date '+%s')"
echo "**** Deployment start time: $(dateFromEpoch "$starttime")"

ipv4_info="$(ip -4 address show | grep -vE 'valid_lft')"
ipv6_info="$(ip -6 address show | grep -vE 'valid_lft|fe80::')"

echo "-------------------------------------------------------------------------------
**** Local IPv4 address information:

${ipv4_info}

-------------------------------------------------------------------------------
**** Local IPv6 address information:

${ipv6_info}

-------------------------------------------------------------------------------"

MEDIA_PATH="$REPO_ROOT/artifacts/guestos/${deployment}/${GIT_REVISION}"
BN_MEDIA_PATH="$REPO_ROOT/artifacts/boundary-guestos/${deployment}/${GIT_REVISION}"
INVENTORY="$REPO_ROOT/testnet/env/$deployment/hosts"

ANSIBLE="ansible-playbook -i $INVENTORY ${ANSIBLE_ARGS[*]} -e ic_git_revision=$GIT_REVISION -e ic_media_path=\"$MEDIA_PATH\""
if ! boundary_nodes_exists $INVENTORY; then
    USE_BOUNDARY_NODES="false"
elif [[ "${USE_ICOS_BOUNDARY_NODE_VMs}" == "true" ]]; then
    ANSIBLE+=" -e bn_media_path=\"$BN_MEDIA_PATH\" -e ic_boundary_node_image=boundary"
else
    ANSIBLE+=" -e ic_boundary_node_image=generic --skip-tags "boundary_node_vm""
fi

cd "$REPO_ROOT/ic-os/guestos"

pushd "$REPO_ROOT/testnet/ansible" >/dev/null
DESTROY_OUT=$(mktemp /tmp/icos-deploy.sh.XXXXXX)
echo "**** Start destroying old deployment (log $DESTROY_OUT)"
# We're invoking ansible as a quoted command, so all given ansible arguments need to be properly quoted as well, hence printf
script --quiet --return "$DESTROY_OUT" --command "set -x; $(printf '%q ' $ANSIBLE) icos_network_redeploy.yml -e ic_state=destroy" >/dev/null 2>&1 &
DESTROY_PID=$!
popd >/dev/null

# Ensure we kill these on CTRL+C or failure
trap 'echo "EXIT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' EXIT

echo "**** Build USB sticks for IC nodes"
rm -rf "$MEDIA_PATH"
mkdir -p "$MEDIA_PATH"
"$REPO_ROOT/testnet/env/${deployment}/hosts" --media-json >"$MEDIA_PATH/${deployment}.json"

"$REPO_ROOT/ic-os/guestos/scripts/build-deployment.sh" \
    --debug \
    --input="$MEDIA_PATH/${deployment}.json" \
    --output="$MEDIA_PATH" \
    --git-revision=$GIT_REVISION \
    --whitelist="$REPO_ROOT/testnet/env/${deployment}/provisional_whitelist.json" \
    --dkg-interval-length=$DKG_INTERVAL_LENGTH \
    --max-ingress-bytes-per-message=$MAX_INGRESS_BYTES_PER_MESSAGE \
    $WITH_TESTNET_KEYS

if [[ "${USE_ICOS_BOUNDARY_NODE_VMs}" == "true" ]]; then
    echo "-------------------------------------------------------------------------------"
    echo "**** Build USB sticks for boundary nodes"
    cd "$REPO_ROOT/ic-os/boundary-guestos"
    rm -rf "$BN_MEDIA_PATH"
    mkdir -p "$BN_MEDIA_PATH"

    "$REPO_ROOT"/testnet/env/${deployment}/hosts --media-json >"$BN_MEDIA_PATH/${deployment}.json"

    "$REPO_ROOT"/ic-os/boundary-guestos/scripts/build-deployment.sh \
        --input="$BN_MEDIA_PATH/${deployment}.json" \
        --output="$BN_MEDIA_PATH" \
        --git-revision=$GIT_REVISION

    echo "**** Build boundary node VM disk image"
    VERSION=$(git rev-parse --verify HEAD)
    ./scripts/build-disk-image.sh -o "$BN_MEDIA_PATH/disk.img" -v $VERSION -p "root"
    echo "-------------------------------------------------------------------------------"
fi

# In case someone wants to deploy with a locally built disk image the following lines contain
# the necessary commands.

# echo "**** Remove previous disk image"
# rm -f $HOME/disk.*

# echo "**** Build disk image"
# ./scripts/build-disk-image.sh -o "$MEDIA_PATH/disk.img"

cd "$REPO_ROOT/testnet/ansible"

# Wait on the destroy to finish
echo "**** Finishing destroy"
DESTROY_STATUS=0
wait $DESTROY_PID || DESTROY_STATUS=1
cat "$DESTROY_OUT" || true
if [[ $DESTROY_STATUS -ne 0 ]]; then
    exit $(tail -1 "$DESTROY_OUT" | sed -re "s/.*=\"([0-9]+).*/\1/")
fi
rm -f "$DESTROY_OUT"

echo "**** Create new IC instance"
$ANSIBLE icos_network_redeploy.yml -e ic_state="create"

echo "**** Start VMs"
$ANSIBLE icos_network_redeploy.yml -e ic_state="start"

if [[ "${USE_BOUNDARY_NODES}" == "true" ]]; then
    pushd "$REPO_ROOT/testnet"
    BOUNDARY_OUT=$(mktemp /tmp/icos-deploy.sh.XXXXXX)
    if [[ "${USE_ICOS_BOUNDARY_NODE_VMs}" == "true" ]]; then
        # The new boundary node VM still needs a couple of configuration steps via ansible
        echo "**** Installing boundary node VMs (log $BOUNDARY_OUT)"
        # We're invoking ansible as a quoted command, so all given ansible arguments need to be properly quoted as well, hence printf
        script --quiet --return "$BOUNDARY_OUT" --command "set -x; $(printf '%q ' $ANSIBLE) -l boundary icos_test_bnvm.yml" >/dev/null 2>&1 &
    else
        echo "**** Installing boundary nodes (log $BOUNDARY_OUT)"
        # We're invoking ansible as a quoted command, so all given ansible arguments need to be properly quoted as well, hence printf
        script --quiet --return "$BOUNDARY_OUT" --command "set -x; $(printf '%q ' $ANSIBLE) -l boundary icos_test.yml" >/dev/null 2>&1 &
    fi
    BOUNDARY_PID=$!
    popd
fi

echo "**** Install NNS canisters"
$ANSIBLE icos_network_redeploy.yml -e ic_state="install"

echo "**** Start monitoring"
NNS_IP=$("$INVENTORY" --nodes | head -n1 | awk '{print $2}')
"$MEDIA_PATH/bin/ic-admin" --nns-url "https://[$NNS_IP]:8080" get-subnet-public-key 0 "$MEDIA_PATH/nns-public-key.pem"
$ANSIBLE ic_p8s_network_update.yml -e yes_i_confirm=yes
$ANSIBLE ic_p8s_service_discovery_install.yml -e yes_i_confirm=yes -e nns_public_key_path="$MEDIA_PATH/nns-public-key.pem"

if [[ "${USE_BOUNDARY_NODES}" == "true" ]]; then
    echo "**** Finishing boundary node deployment"
    BOUNDARY_STATUS=0
    wait "$BOUNDARY_PID" || BOUNDARY_STATUS=1
    cat "$BOUNDARY_OUT" || true
    if [[ $BOUNDARY_STATUS -ne 0 ]]; then
        exit $(tail -1 "$BOUNDARY_OUT" | sed -re "s/.*=\"([0-9]+).*/\1/")
    fi
    rm -f "$BOUNDARY_OUT"
fi

endtime="$(date '+%s')"
echo "**** Completed deployment at $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"
duration=$((endtime - starttime))
echo "**** $((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

trap - EXIT
