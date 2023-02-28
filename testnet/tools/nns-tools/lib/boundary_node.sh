#!/bin/bash

configure_boundary_nodes_for_recovered_nns() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local TESTNET=$2

    local ORIGINAL_NNS_ID="tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
    local NNS_ROOT_KEY=$(mktemp)

    # Get the new public key from recovered NNS
    $IC_ADMIN --nns-url "$NNS_URL" \
        get-subnet-public-key \
        "$ORIGINAL_NNS_ID" \
        $NNS_ROOT_KEY

    local NNS_CONF="nns_url=$NNS_URL"

    pushd "$(repo_root)/testnet/env/$TESTNET"
    BOUNDARY_NODES=$(HOSTS_INI_FILENAME=hosts_unassigned.ini ./hosts --nodes | grep boundary | cut -d' ' -f2)

    NNS_SUBNET_NODE=$(get_node_for_subnet "$NNS_URL" "$ORIGINAL_NNS_ID")

    local SSH_ARGS="-A -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

    for NODE in $BOUNDARY_NODES; do
        echo "Stopping ic-registry-replicator..."
        ssh $SSH_ARGS "admin@$NODE" "sudo systemctl stop ic-registry-replicator"
        echo "Updating configuration for boundary node..."
        scp -vvv -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "$NNS_ROOT_KEY" "admin@[$NODE]:/var/lib/admin/nns_public_key.pem"
        ssh $SSH_ARGS "admin@$NODE" "cat /var/lib/admin/nns_public_key.pem | sudo tee /boot/config/nns_public_key.pem"

        ssh $SSH_ARGS "admin@$NODE" "echo $NNS_CONF | sudo tee /boot/config/nns.conf"

        echo "Deleting current NNS store..."
        # Delete the store
        ssh $SSH_ARGS "admin@$NODE" "sudo rm -rf /var/opt/registry/store"

        echo "Reconfigure ic-registry-replicator..."
        ssh $SSH_ARGS "admin@$NODE" "sudo systemctl restart setup-ic-registry-replicator"
        echo "Restarting ic-registry-replicator..."
        ssh $SSH_ARGS "admin@$NODE" "sudo systemctl start ic-registry-replicator"

        echo "Updating nix configuration on boundary node to work with recovered NNS topology"
        # Update nginx config to not randomly choose where to get root key from (it uses recovered NNS topology some of which point to mainnet nodes)
        ssh $SSH_ARGS "admin@$NODE" "cat /etc/nginx/conf.d/001-mainnet-nginx.conf \
            | sed 's/\$random_route_subnet_id/$ORIGINAL_NNS_ID/g' \
            | sed 's/\$random_route_subnet_type/system/g' \
            | sed 's/\$random_route_node_id/$NNS_SUBNET_NODE/g' \
            | sudo tee /run/ic-node/001-mainnet-nginx.conf >/dev/null"

        ssh $SSH_ARGS "admin@$NODE" "sudo mount --bind /run/ic-node/001-mainnet-nginx.conf /etc/nginx/conf.d/001-mainnet-nginx.conf"
        ssh $SSH_ARGS "admin@$NODE" "sudo nginx -s reload"
        echo "Done configuring boundary node $NODE"
    done
}
