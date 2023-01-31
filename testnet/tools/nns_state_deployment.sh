#!/bin/bash

set -e
source $(dirname "$0")/lib.sh

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
print_green Tmp Dir: $TMP_DIR
WORKING_DIR="$TMP_DIR/recovery/working_dir"
DATA_DIR="$WORKING_DIR/data"
IC_ADMIN="$TMP_DIR/ic-admin"
IC_REPLAY="$TMP_DIR/ic-replay"
IC_RECOVERY="$TMP_DIR/ic-recovery"

# Select all IPs
export HOSTS_INI_FILENAME=hosts_unassigned.ini
cd $SCRIPT_DIR/../env/$TESTNET/
NNS_IP=$(./hosts --nodes | grep "\.0\.0" | head -1 | cut -d ' ' -f 2)
AUX_IP=$(./hosts --nodes | grep aux | cut -d ' ' -f 2)
NNS_URL="http://[$NNS_IP]:8080"
cd -

print_green "NNS_URL=$NNS_URL"

mkdir -p $TMP_DIR

step 1 "Download all binary tools." || (
    log "Downloading to $TMP_DIR ..."
    for tool in ic-replay ic-recovery ic-admin sandbox_launcher canister_sandbox; do
        if [ ! -f "$TMP_DIR/$tool" ]; then
            install_binary "$tool" "$VERSION" "$TMP_DIR"
        fi
    done
)

step 2 "Deploy an IC to the testnet." || (
    LOG_FILE="$TMP_DIR/2_testnet_deployment_log.txt"
    log "Log of the deployment is written to $LOG_FILE ..."
    $SCRIPT_DIR/icos_deploy.sh --boundary-dev-image --dkg-interval-length 19 "$TESTNET" --git-revision "$VERSION" --hosts-ini $HOSTS_INI_FILENAME >$LOG_FILE 2>&1
)

# Get all unassigned nodes.
mapfile -d " " -t node_ids <<<"$($TMP_DIR/ic-admin --nns-url "$NNS_URL" get-topology | jq -r '.topology.unassigned_nodes | map_values(.node_id) | join(" ")')"

step 3 "Fetch the NNS state from the backup pod." || (
    LOG_FILE="$TMP_DIR/3_nns_state_fetching_log.txt"
    log "writing log to $LOG_FILE ..."
    mkdir -p "$DATA_DIR"
    # Repeat the command until it succeeded
    while ! rsync -e "ssh $SSH_ARGS" -av dev@zh1-pyr07.dc1.dfinity.network:~/nns_state/ "$DATA_DIR/" >"$LOG_FILE"; do
        echo "rsync failed with status code $?"
        sleep 1
    done
    scp $SSH_ARGS "admin@[$NNS_IP]:/run/ic-node/config/ic.json5" "$WORKING_DIR/"
)

step 4 "Create a neuron followed by trusted neurons." || (
    LOG_FILE="$TMP_DIR/4_create_neuron_leader.txt"
    VARS_FILE="$TMP_DIR/output_vars_4.sh"
    log "writing log to $LOG_FILE ..."
    # Giving our Neuron 1 billion ICP so it can pass all proposals instantly
    NEURON_ID=$($IC_REPLAY --subnet-id $ORIGINAL_NNS_ID --data-root "$DATA_DIR" "$WORKING_DIR/ic.json5" with-neuron-for-tests $CONTROLLER 100000000000000000 | grep "neuron_id=" | cut -d '=' -f 2)

    log "Created neuron with id=$NEURON_ID"
    $IC_REPLAY --subnet-id $ORIGINAL_NNS_ID --data-root "$DATA_DIR" "$WORKING_DIR/ic.json5" with-trusted-neurons-following-neuron-for-tests $NEURON_ID $CONTROLLER &>/dev/null
    log "Recording variable output to $VARS_FILE..."
    echo "export NEURON_ID=$NEURON_ID" >"$VARS_FILE"
)

source "$TMP_DIR/output_vars_4.sh"

step 5 "Give our principal 1 million ICP" || (
    if [ ! -z "$PEM" ]; then
        #Give our user 1 million ICP
        CURRENT_DFX_ID=$(dfx identity whoami)
        dfx identity import --force --disable-encryption tmp_id_for_script "$PEM"
        dfx identity use tmp_id_for_script
        USER_ACCOUNT_IDENTIFIER=$(dfx ledger account-id)
        dfx identity use "$CURRENT_DFX_ID"
        dfx identity remove tmp_id_for_script
        $IC_REPLAY --subnet-id $ORIGINAL_NNS_ID --data-root "$DATA_DIR" "$WORKING_DIR/ic.json5" with-ledger-account-for-tests "$USER_ACCOUNT_IDENTIFIER" 100000000000000
    fi
)

step 6 "Recover the NNS subnet to the first unassigned node." || (
    # Get all unassigned nodes
    mapfile -d " " -t node_ids <<<"$($IC_ADMIN --nns-url "$NNS_URL" get-topology | jq -r '.topology.unassigned_nodes | map_values(.node_id) | join(" ")')"
    export UPLOAD_IP=$($IC_ADMIN --nns-url "$NNS_URL" get-node "${node_ids[0]}" | grep ip_addr | cut -d '"' -f4)
    log "Unassigned nodes: ${node_ids[@]}"
    log "IP of the first unassigned node: $UPLOAD_IP"

    # Create a script driving the subnet recovery via ic-recovery tool.
    echo "#!/bin/bash" >$TMP_DIR/driver.sh
    echo "echo y && echo "" && echo y && echo y && echo y && echo n && echo y && echo y && echo y && echo y && echo y && echo y && echo y && echo y" >>$TMP_DIR/driver.sh
    chmod +x $TMP_DIR/driver.sh

    # Run the recovery.
    LOG_FILE="$TMP_DIR/6_nns_recovery_log.txt"
    VARS_FILE="$TMP_DIR/output_vars_6.sh"

    log "Running ic-recovery, this can take a few minutes... "
    log "Use the following command to see the progress log: tail -f $LOG_FILE"
    $TMP_DIR/driver.sh | $IC_RECOVERY --dir $TMP_DIR -r $NNS_URL --replica-version $VERSION --test nns-recovery-failover-nodes \
        --subnet-id $ORIGINAL_NNS_ID \
        --validate-nns-url $NNS_URL \
        --aux-ip $AUX_IP --aux-user admin \
        --parent-nns-host-ip $NNS_IP \
        --replica-version $VERSION \
        --upload-node $UPLOAD_IP \
        --replacement-nodes ${node_ids[0]} >$LOG_FILE 2>&1

    log "Recovery done, waiting until the new NNS starts up @ $UPLOAD_IP ..."
    # TODO: NNS1-2024
    until ssh $SSH_ARGS "admin@${UPLOAD_IP}" 'journalctl | grep -q "Ready for interaction"' &>/dev/null; do
        print_blue "Waiting for the subnet to resume..."
        sleep 2
    done

    # step 6 "Move the remaining unassigned nodes over so they are controlled by the new NNS" || (
    # Get the remaining unassigned nodes
    log "Moving unassigned nodes to the new NNS..."
    mapfile -d " " -t node_ids <<<"$($IC_ADMIN --nns-url "$NNS_URL" get-topology | jq -r '.topology.unassigned_nodes | map_values(.node_id) | join(" ")')"
    log "Unassigned nodes: ${node_ids[@]}"

    for NODE in ${node_ids[@]}; do
        log "Moving node $NODE to NNS at $UPLOAD_IP ..."
        NODE_IP=$($IC_ADMIN --nns-url "$NNS_URL" get-node "$NODE" | grep ip_addr | cut -d '"' -f4)
        log "Node $NODE has IP $NODE_IP"
        move_node_to_new_nns "$UPLOAD_IP" "$NODE_IP"
    done

    echo "export UPLOAD_IP=\"$UPLOAD_IP\"" >"$VARS_FILE"
    echo "export NEW_NNS_IP=\"$UPLOAD_IP\"" >>"$VARS_FILE"
    echo "export NEW_NNS_URL=\"http://[$UPLOAD_IP]:8080\"" >>"$VARS_FILE"
    echo "export UNASSIGNED_NODES=\"${node_ids[@]}\"" >>"$VARS_FILE"

    print_green "NNS state deployment has finished! Use neuron_id=$NEURON_ID and nns_url=http://[$UPLOAD_IP]:8080 for interactions with $TESTNET."
)
source "$TMP_DIR/output_vars_6.sh"

step 7 "Test the recovery." || (
    if [ -z "$PEM" ]; then
        print_red "No PEM file specified, skipping further tests..."
    else
        # set +e
        log "Creating a test proposal..."
        $IC_ADMIN --nns-url "http://[$UPLOAD_IP]:8080" -s $PEM propose-to-bless-replica-version-flexible "TEST" "https://host.com/file.tar.gz" "deadbeef" --proposer $NEURON_ID --summary "Blessing test replica"
        if ssh $SSH_ARGS "admin@${UPLOAD_IP}" 'journalctl | grep -i proposal' | grep -q succeeded; then
            print_green "SUCCESS! NNS is up and running, the neuron $NEURON_ID can successfully create proposals."
        else
            print_red "$NEURON_ID could not create proposals with the PEM file provided."
        fi
        set -e
    fi
)

VARS_FILE=$TMP_DIR/output_vars_nns_state_deployment.sh

echo export OLD_NNS_IP="$NNS_IP" >$VARS_FILE
echo export NNS_IP="$NEW_NNS_IP" >>$VARS_FILE
echo export OLD_NNS_URL="http://[$NNS_IP]:8080" >>$VARS_FILE
echo export NNS_URL="$NEW_NNS_URL" >>$VARS_FILE
echo export NEURON_ID="$NEURON_ID" >>$VARS_FILE
echo export UNASSIGNED_NODES=\"$UNASSIGNED_NODES\" >>$VARS_FILE

# echo the vars for cases when script deletes $TMP_DIR
cat "$VARS_FILE"

if [ -z "$DIR" ]; then
    rm -rf $TMP_DIR
else
    echo "Output Variables captured in $VARS_FILE"
fi
