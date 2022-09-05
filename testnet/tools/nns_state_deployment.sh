#!/bin/bash

set -e

if (($# < 3)); then
    echo >&2 "Usage: <TESTNET> <REPLICA_VERSION> <PRINCIPAL_ID> [<PATH_TO_PEM>]"
    echo ""
    echo "NOTE: To use this script, your public key should be present on pyr07 backup pod! (ask for help on #backup-ops Slack channel)"
    echo ""
    echo "REPLICA_VERSION    A build id of a downloadable image."
    echo "TESTNET            A testnet which supports unassigned nodes. (hosts_unassigned.ini should be present!)"
    echo "PRINCIPAL_ID       The controller who will controll the neuron created after the deployment."
    echo "                   This neuron will be followed by trusted neurons and can be used to create proposals and vote on them."
    echo "PATH_TO_PEM        is an optional parameter and is used to automatically test if the created neuron can create proposals."
    exit 1
fi

TESTNET=$1
VERSION=$2
CONTROLLER=$3
PEM=$4
SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
ORIGINAL_NNS_ID=tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe
SSH_ARGS="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
TMP_DIR=${DIR:-$(mktemp -d)}

mkdir -p $TMP_DIR

# Download all binary tools.
for tool in ic-replay ic-recovery ic-admin sandbox_launcher canister_sandbox; do
    if [ ! -f "$TMP_DIR/$tool" ]; then
        echo "Downloading $tool..."
        curl "https://download.dfinity.systems/ic/$VERSION/release/$tool.gz" | zcat >"$TMP_DIR/$tool"
        chmod +x "$TMP_DIR/$tool"
    fi
done

# Select all IPs
export HOSTS_INI_FILENAME=hosts_unassigned.ini
cd $SCRIPT_DIR/../env/$TESTNET/
NNS_IP=$(./hosts --nodes | grep "\.0\.0" | head -1 | cut -d ' ' -f 2)
AUX_IP=$(./hosts --nodes | grep aux | cut -d ' ' -f 2)
NNS_URL="http://[$NNS_IP]:8080"
cd -

# Deploy an IC to the testnet.
$SCRIPT_DIR/icos_deploy.sh --no-boundary-nodes --dkg-interval-length 19 "$TESTNET" --git-revision "$VERSION" --hosts-ini hosts_unassigned.ini

# Fetch the NNS state from the backup pod.
WORKING_DIR="$TMP_DIR/recovery/working_dir"
DATA_DIR="$WORKING_DIR/data"
mkdir -p "$DATA_DIR"
# Repeat the command until it succeeded
while ! rsync -e "ssh $SSH_ARGS" -av dev@zh1-pyr07.dc1.dfinity.network:~/nns_state/ "$DATA_DIR/"; do
    echo "rsync failed with status code $?"
    sleep 1
done
scp $SSH_ARGS "admin@[$NNS_IP]:/run/ic-node/config/ic.json5" "$WORKING_DIR/"

# Create a neuron followed by trusted neurons.
NEURON_ID=$($TMP_DIR/ic-replay --subnet-id $ORIGINAL_NNS_ID --data-root "$DATA_DIR" "$WORKING_DIR/ic.json5" with-neuron-for-tests $CONTROLLER 1000000000 | grep "neuron_id=" | cut -d '=' -f 2)
echo "Created neuron with id=$NEURON_ID"
$TMP_DIR/ic-replay --subnet-id $ORIGINAL_NNS_ID --data-root "$DATA_DIR" "$WORKING_DIR/ic.json5" with-trusted-neurons-following-neuron-for-tests $NEURON_ID $CONTROLLER &>/dev/null

# Get all unassigned nodes.
mapfile -d " " -t node_ids <<<"$($TMP_DIR/ic-admin --nns-url "$NNS_URL" get-topology | jq -r '.topology.unassigned_nodes | map_values(.node_id) | join(" ")')"

UPLOAD_IP=$($TMP_DIR/ic-admin --nns-url "$NNS_URL" get-node "${node_ids[0]}" | grep ip_addr | cut -d '"' -f4)

# Create a script driving the subnet recovery via ic-recovery tool
echo "#!/bin/bash" >$TMP_DIR/driver.sh
echo "echo y && echo "" && echo y && echo y && echo y && echo y && echo y && echo y && echo y && echo y && echo y && echo y && echo y && echo y" >>$TMP_DIR/driver.sh
chmod +x $TMP_DIR/driver.sh

# Recover the NNS subnet.
$TMP_DIR/driver.sh | $TMP_DIR/ic-recovery --dir $TMP_DIR -r $NNS_URL --replica-version $VERSION --test nns-recovery-failover-nodes \
    --subnet-id $ORIGINAL_NNS_ID \
    --validate-nns-url $NNS_URL \
    --aux-ip $AUX_IP --aux-user admin \
    --parent-nns-host-ip $NNS_IP \
    --replica-version $VERSION \
    --upload-node $UPLOAD_IP \
    --replacement-nodes ${node_ids[@]}

until ssh $SSH_ARGS "admin@${UPLOAD_IP}" 'journalctl | grep -q "Ready for interaction"' &>/dev/null; do
    echo "Waiting for the subnet to resume..."
    sleep 2
done

echo "NNS state deployment has finished! Use neuron_id=$NEURON_ID and nns_url=http://[$UPLOAD_IP]:8080 for interactions with $TESTNET."

# Test the recovery.
if [ -z "$PEM" ]; then
    echo "No PEM file specified, skipping further tests..."
else
    echo "Creating a test proposal..."
    $TMP_DIR/ic-admin --nns-url "http://[$UPLOAD_IP]:8080" -s $PEM propose-to-bless-replica-version-flexible "TEST" "https://host.com/file.tar.gz" "deadbeef" --proposer $NEURON_ID
    if ssh $SSH_ARGS "admin@${UPLOAD_IP}" 'journalctl | grep -i proposal' | grep -q succeeded; then
        echo "SUCCESS! NNS is up and running, the neuron $NEURON_ID can successfully create proposals."
    fi
fi

rm -rf $TMP_DIR
