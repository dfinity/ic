# NNS Tools

A small collection of tools for testing NNS canisters and upgrades on testnets.

## nns_dev_testnet.sh

This script creates a testnet with mainnet state using a stable shared identity and modifies it in a few ways for development purposes.
1. Adds an application subnet.
2. Sets CMC default subnet list to that application subnet.
3. Creates a cycles wallet for our shared principal on the application subnet.
4. Configures SNS-W to create SNS's on application subnet, and to respond to our principal's wallet.
5. Uploads the latest SNS Wasms into SNS-W canister

It then stores all of the variables in a directory (which is output) so they can be easily referenced for
interaction with the subnet

### Example usage of nns_dev_testnet.sh

#### Run the entire script
```
DIR=/tmp/$USER-nns-test/ ./nns_state_with_sns_wasms.sh small02 1a2d86e9d66d93c4a9a9a147774577c377ce0c66
```

#### Run only the full step 1 of the script.
```
DIR=/tmp/$USER-nns-test/ STEPS='1' ./nns_state_with_sns_wasms.sh small02 1a2d86e9d66d93c4a9a9a147774577c377ce0c66
```

#### Within step 1, run only substeps 3 and 4 of nns_state_deployment.sh.
```
DIR=/tmp/$USER-nns-test/ STEPS='1' DEPLOYMENT_STEPS='[34]' ./nns_state_with_sns_wasms.sh small02 1a2d86e9d66d93c4a9a9a147774577c377ce0c66
```

### Interacting afterwards
```
source $DIRECTORY/output_vars_nns_dev_testnet.sh
dfx canister --network $NNS_URL call qaa6y-5yaaa-aaaaa-aaafa-cai get_sns_subnet_ids '(record {})'
$IC_ADMIN --nns-url "$NNS_URL" get-topology

# You define the location of your $CONFIG_FILE, then you can deploy
$SNS_CLI deploy --network "$SUBNET_URL" \
        --wallet-canister-override "$WALLET_CANISTER" \
        --init-config-file "$CONFIG_FILE"
```

Note: When making calls _through_ the wallet canister with `dfx` or `sns` you need to set the `--network` argument
to be the $SUBNET_URL, as the $NNS_URL points at the NNS replica and will not route your requests to the correct subnet.