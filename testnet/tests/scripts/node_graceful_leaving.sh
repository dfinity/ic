#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Graceful Node Removal

Goal:: Ensure the subnet committee size drops to half and the usbnet continues

Description::
In this test we deploy a subnet and then propose a graceful removal of half of its nodes.
Then we monitor a couple of metrics to make sure that the nodes really left and the committee
size drops to the half. Then we also make sure the certified height grows proving that the
subnet is making progress.

Runbook::
. set up the testnet
. propose the node removal with half of the nodes

Success::
. the committee size drops
. the certified height keeps growing

end::catalog[]
DOC

set -euo pipefail

function exit_usage() {
    echo >&2 "Usage: $0 <testnet>  <results_dir>"
    echo >&2 "$0 medium01 ./results/"
    exit 1
}

if (($# != 2)); then
    exit_usage
fi

testnet="$1"
results_dir="$(
    mkdir -p "$2"
    realpath "$2"
)"
experiment_dir="$results_dir/${testnet}-$(date +%s)"
export experiment_dir

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

starttime="$(date '+%s')"
echo "Start time: $(dateFromEpoch "$starttime")"

# Determine the URL of the NNS
hosts_file_path="$PROD_SRC/env/$testnet/hosts"
HOSTS_INI_ARGUMENTS=()

if [[ -n "${TEST_NNS_URL-}" ]]; then
    nns_url="${TEST_NNS_URL}"
else
    # Deploy the testnet
    deploy_with_timeout "$testnet" \
        --dkg-interval-length 19 \
        --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"

    nns_url=$(
        cd "$PROD_SRC"
        ansible-inventory -i "$hosts_file_path" --list \
            | jq -r -L"${PROD_SRC}/jq" 'import "ansible" as ansible;
            ._meta.hostvars |
            [
                with_entries(select(.value.subnet_index==0))[] |
                ansible::interpolate |
                .api_listen_url
            ] |
            first'
    )
fi

echo "Testnet deployment successful. Test starts now."

# Ensure we kill all background processes on CTRL+C
# shellcheck disable=SC2064
trap "echo 'SIGINT received, killing all jobs'; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1" INT

# set -x

IFS=' ' read -r -a node_ids <<<"$(ic-admin --nns-url "$nns_url" get-subnet 0 | jq -r '.records[0].value.membership | join(" ")')"

num_nodes=${#node_ids[@]}
# He we drop half of nodes starting from the second node. We do this because we use the IP address
# of the first node in the NNS URL.
# shellcheck disable=SC2124
leaving_nodes="${node_ids[@]:1:$((num_nodes / 2))}"
metrics_url=${nns_url/8080/9090}

committee_size="$(curl -s "$metrics_url" | grep consensus_dkg_current_committee_size | tail -1 | cut -d ' ' -f2)"
transport_flow_count="$(curl -s "$metrics_url" | grep -e "^transport_flow_state" | cut -d " " -f 2 | awk '{s+=$1} END {print s}')"

# Make the nodes leave the subnet
# shellcheck disable=SC2086
ic-admin --nns-url "$nns_url" propose-to-remove-nodes-from-subnet --test-neuron-proposer $leaving_nodes

# Grab the committee size metric until it changes and check if it is half of the original size.
while true; do
    current_committee_size="$(curl -s "$metrics_url" | grep consensus_dkg_current_committee_size | tail -1 | cut -d ' ' -f2)"
    if ((committee_size >= 2 * current_committee_size)); then
        # Once the committee size dropped, check if the certified height grows, proving the usbnet is makeing progress.
        certified_height="$(curl -s "$metrics_url" | grep certification_last_certified_height | tail -1 | cut -d " " -f2)"
        while true; do
            # Now we make sure that the transport flow count has dropped as well
            while true; do
                current_transport_flow_count="$(curl -s "$metrics_url" | grep -e "^transport_flow_state" | cut -d " " -f 2 | awk '{s+=$1} END {print s}')"
                if ((current_transport_flow_count < transport_flow_count)); then
                    echo "Transport flow count dropped as expected!"
                    break
                else
                    echo "Waiting for the transport flow count to drop..."
                    sleep 5
                fi
            done
            current_certified_height="$(curl -s "$metrics_url" | grep certification_last_certified_height | tail -1 | cut -d " " -f2)"
            if ((current_certified_height > certified_height)); then
                echo "New committee size successfuly reached: $current_committee_size (old size: $committee_size). SUCCESS!"
                break 2
            else
                echo "Waiting for certified height to grow..."
                sleep 5
            fi
        done
    else
        echo "Waiting for committee size to drop..."
        sleep 5
    fi
done

success "Committee size and transport_flow_count changed as expected."

endtime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."
