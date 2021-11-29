#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Firewall test

Goal:: Test that the nodes update the firewall rules based on a proposal to the registry

Runbook::
. Start ic with at least one application subnet
. Fetch the existing firewall config from one of the nodes
. Update this config to exclude port 9090 and propose it to the NNS
. Check that the content of the firewall rules file has changed in all nodes
. Check that port 9090 is indeed inaccessible
. Check that other ports are still accessible
. Propose the original config as an update to the registry
. Check that port 9090 is accessible again

Success::
. All nodes have the expected config in their filesystem after first proposal
. Port 9090 is inaccessible after first proposal
. Port 8080 is accessible after first proposal
. Port 9090 is accessible after second proposal

end::catalog[]
DOC

set -euo pipefail

function exit_usage() {
    echo >&2 "Usage: $0 <testnet> <results_dir>"
    echo >&2 "$0 p2p_15 30 40 250b ./results/"
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
experiment_dir="$results_dir/${testnet}-firewall_test-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

#
# Preparatory work
#

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"

echo '
{
 "BytesDeliveredRate": bytes_delivered_rate
}
' >>"$experiment_dir/data_to_upload/BytesDeliveredRate.json"

# Deploy the testnet
deploy_with_timeout "$testnet" --git-revision "$GIT_REVISION"

echo "Testnet deployment successful. Test starts now."

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

# START TEST

echo "########################################################################"
echo "# Starting firewall test"
echo "########################################################################"
echo ""

cd "$PROD_SRC"

NNS_URL=$(
    ansible-inventory -i "env/$testnet/hosts" --list \
        --list | jq -L./jq -r \
        "import \"ansible\" as ansible; . as \$o | .nns.hosts[0] | \$o._meta.hostvars[.] | ansible::interpolate | .api_listen_url"
)

echo "Set NNS_URL to $NNS_URL"

# Load firewall config from some node
host=$(
    cd "$PROD_SRC"
    ansible-inventory -i "env/$testnet/hosts" --list \
        | jq -L"${PROD_SRC}/jq" -r 'import "ansible" as ansible;
               ._meta.hostvars |
               [
                 with_entries(select(.value.subnet_index==1))[] |
                 ansible::interpolate |
                 .ansible_host
               ][0]'
)

echo "Fetching config from node $host"

# shellcheck disable=SC2002
ic_config=$(ssh -o "StrictHostKeyChecking no" -o "UserKnownHostsFile=/dev/null" admin@"$host" sudo cat "/opt/ic/share/ic.json5.template")
firewall_file_path_on_node=$(echo "$ic_config" | tr '\n' '\a' | grep -o 'firewall\:.*config_file: \"[^\"]*\"' | tr '\a' ' ' | sed 's/.*config_file\: \"\(.*\)\"/\1/')
echo "Firewall file on nodes: $firewall_file_path_on_node"

original_fw_config_content_file=$experiment_dir/fw_config_original
fw_config_content_file=$experiment_dir/fw_config

echo "Downloading current firewall config from $host"
ssh -o "StrictHostKeyChecking no" -o "UserKnownHostsFile=/dev/null" admin@"$host" sudo cat "$firewall_file_path_on_node" | sed -e ':a;N;$!ba;s/,\n/,/' >"$original_fw_config_content_file"

# Modify the rules so that we disable new metrics connections
# shellcheck disable=SC2002
config_content=$(cat "$original_fw_config_content_file" | sed 's/9090, //g')

# Fetch the IPv6 prefixes from the config and put them into ipv6_prefixes
if [ -z "$(echo "$config_content" | tr '\n' '\a' | grep -o "define IPV6_PREFIXES={[^}]*}" || true)" ]; then
    echo "No IPv6 prefixes found in config"
else
    ipv6_prefixes=$(echo "$config_content" | tr '\n' '\a' | grep -o "define IPV6_PREFIXES={[^}]*}" | tr '\a' '\n' | tail -n+2 | sed '$d' | tr '\n' ' ' | sed 's/ //g')
fi

# shellcheck disable=SC2001
if [ -z "$(echo "$ipv6_prefixes" | sed "s/\W//g")" ]; then
    ipv6_prefixes='-'
fi

# Fetch the IPv4 prefixes from the config and put them into ipv4_prefixes
if [ -z "$(echo "$config_content" | tr '\n' '\a' | grep -o "define IPV4_PREFIXES={[^}]*}" || true)" ]; then
    echo "No IPv4 prefixes found in config"
else
    ipv4_prefixes=$(echo "$config_content" | tr '\n' '\a' | grep -o "define IPV4_PREFIXES={[^}]*}" | tr '\a' '\n' | tail -n+2 | sed '$d' | tr '\n' ' ' | sed 's/ //g')
fi

# shellcheck disable=SC2001
if [ -z "$(echo "$ipv4_prefixes" | sed "s/\W//g")" ]; then
    ipv4_prefixes='-'
fi

# Put a placeholder for the prefixes instead of the actual prefixes (we want this part to be dynamically created by node manager)
# shellcheck disable=SC2001
config_content=$(echo "$config_content" | tr '\n' '\a' | sed 's/define IPV6_PREFIXES={[^}]*}/define IPV6_PREFIXES={\n  << ipv6_prefixes >>\n}/g' | sed 's/define IPV4_PREFIXES={[^}]*}/define IPV4_PREFIXES={\n  << ipv4_prefixes >>\n}/g' | tr '\a' '\n')
original_config_content=$(tr '\n' '\a' <"$original_fw_config_content_file" | sed 's/define IPV6_PREFIXES={[^}]*}/define IPV6_PREFIXES={\n  << ipv6_prefixes >>\n}/g' | sed 's/define IPV4_PREFIXES={[^}]*}/define IPV4_PREFIXES={\n  << ipv4_prefixes >>\n}/g' | tr '\a' '\n')

# Write the content of the firewall config to a file (to be read by ic-admin)
echo "$config_content" >"$fw_config_content_file"
echo "$original_config_content" >"$original_fw_config_content_file"

echo "Proposing the following config:"
echo "$config_content"
echo ""
echo "With the following IPv6 prefixes:"
echo "$ipv6_prefixes"
echo ""
echo "And with the following IPv4 prefixes:"
echo "$ipv4_prefixes"
echo ""

#echo "Original config:"
#cat "$original_fw_config_content_file"

# Make the proposal

# shellcheck disable=SC2068
PROPOSAL_OUTPUT=$(
    ic-admin --nns-url="$NNS_URL" propose-to-set-firewall-config \
        --test-neuron-proposer -- \
        "$fw_config_content_file" \
        "$ipv4_prefixes" \
        "$ipv6_prefixes"
)
PROPOSAL_ID=$(echo "$PROPOSAL_OUTPUT" | grep -i proposal | grep -oE "[0-9]*")

echo "proposed to set the firewall config (ID: $PROPOSAL_ID)"

echo "Waiting 120 seconds for config to propagate to nodes"
sleep 120

# Fetch the firewall file from the nodes and compare to expected content
hosts=$(
    cd "$PROD_SRC"
    ansible-inventory -i "env/$testnet/hosts" --list \
        | jq -L"${PROD_SRC}/jq" -r 'import "ansible" as ansible;
               ._meta.hostvars |
               [
                 with_entries(select(.value.subnet_index==1))[] |
                 ansible::interpolate |
                 .ipv6
               ] |
               join(" ")'
)

expected_config_path="$experiment_dir"/expected_ruleset
cp "$fw_config_content_file" "$expected_config_path"~
sed -i "s|<< ipv6_prefixes >>|$ipv6_prefixes|g" "$expected_config_path"~
sed -i "s|<< ipv4_prefixes >>|$ipv4_prefixes|g" "$expected_config_path"~

tr '\n' ' ' <"$expected_config_path"~ | sed 's/ //g' >"$expected_config_path"

success=1

echo Checking generated files on all hosts
for host in $hosts; do
    filename="$experiment_dir"/"$host"_ruleset
    echo Checking "$host"
    ssh -o "StrictHostKeyChecking no" -o "UserKnownHostsFile=/dev/null" admin@"$host" sudo cat "$firewall_file_path_on_node" | sed -e ':a;N;$!ba;s/,\n/,/' | tr '\n' ' ' | sed 's/ //g' >"$filename"
    if cmp -s "$expected_config_path" "$filename"; then
        echo "Host $host has the correct config"
    else
        echo "Host $host has an incorrect firewall configuration file!"
        success=0
    fi
done

if [[ $success == 0 ]]; then
    echo "Test failed -- some hosts did not have the correct config"
    echo "* Note: Firewall configuration may be malformed on some nodes now."
    exit 1
fi

echo "Firewall config update succeeded on all nodes!"

for host in $hosts; do
    echo -n Checking port 9090: curling https://["$host"]:9090 and expecting it to hang...
    rc=0
    timeout 5 curl --insecure --tlsv1.3 https://["$host"]:9090 &>/dev/null || rc=$?
    if [ $rc -ne 124 ]; then
        echo FAILED
        echo "Test failed: successfully established connection to port 9090 on host $host"
        echo "* Note: Firewall configuration may be malformed on some nodes now."
        exit 1
    else
        echo SUCCESS
    fi
done

for host in $hosts; do
    echo -n Checking port 8080: curling https://["$host"]:8080 and expecting it to succeed immediately...
    rc=0
    timeout 5 curl --insecure --tlsv1.3 https://["$host"]:8080 &>/dev/null || rc=$?
    if [ $rc == 124 ]; then
        echo FAILED
        echo "Test failed: could not establish connection to port 8080 on host $host"
        echo "* Note: Firewall configuration may be malformed on some nodes now."
        exit 1
    else
        echo SUCCESS
    fi
done

echo ""
echo Connectivity test succeeded

# Restore correct firewall config (by making a new proposal)
# Make the proposal

echo ""
echo Proposing new firewall config -- restore to original configuration
echo ""
echo Config file content:
cat "$original_fw_config_content_file"
echo ""
echo IPv6 Prefixes:
echo "$ipv6_prefixes"
echo ""
echo IPv4 Prefixes:
echo "$ipv4_prefixes"
echo ""

# shellcheck disable=SC2068
PROPOSAL_OUTPUT=$(
    ic-admin --nns-url="$NNS_URL" propose-to-set-firewall-config \
        --test-neuron-proposer -- \
        "$original_fw_config_content_file" \
        "$ipv4_prefixes" \
        "$ipv6_prefixes"
)
PROPOSAL_ID=$(echo "$PROPOSAL_OUTPUT" | grep -i proposal | grep -oE "[0-9]*")

echo "proposed to set the firewall config (ID: $PROPOSAL_ID)"

echo "Waiting 120 seconds for config to propagate"
sleep 120

for host in $hosts; do
    echo -n Checking port 9090: curling https://["$host"]:9090 and expecting it to succeed immediately...
    rc=0
    timeout 5 curl --insecure --tlsv1.3 https://["$host"]:9090 &>/dev/null || rc=$?
    if [ $rc == 124 ]; then
        echo FAILED
        echo "Test failed: could not establish connection to port 9090 on host $host"
        echo "* Note: Firewall configuration may be malformed on some nodes now."
        exit 1
    else
        echo SUCCESS
    fi
done

success "Test completed successfully, firewall modifications were propagated and applied successfully!"

finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."
