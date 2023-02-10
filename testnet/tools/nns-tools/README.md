# NNS Tools

A small collection of tools for testing NNS canisters and upgrades on testnets.

## Spinning up a testnet

### nns_dev_testnet.sh

This script creates a testnet with mainnet state using a stable shared identity and modifies it in a few ways for development purposes.
1. Adds an application subnet.
2. Sets CMC default subnet list to that application subnet.
3. Creates a cycles wallet for our shared principal on the application subnet.
4. Configures SNS-W to create SNS's on application subnet, and to respond to our principal's wallet.
5. Uploads the latest SNS Wasms into SNS-W canister

It then stores all of the variables in a directory (which is output) so they can be easily referenced for
interaction with the subnet

### Example usage of nns_dev_testnet.sh

When running the testnet creation script, a temporary directory is created.  If you would like to use a particular directory
you can set `DIR` in your environment.  In our examples, we do this to make it easier to find the outputs from the 
scripts.

For more information, run `./nns_dev_testnet.sh` without arguments.

#### Run the entire script

```
DIR=/tmp/$USER-nns-test/ ./nns_dev_testnet.sh small02 1a2d86e9d66d93c4a9a9a147774577c377ce0c66
```

#### Run only the full step 1 of the script.

Sometimes, during testnet setup or when developing the script, you may want to only run some parts.  To see the parts,
read the script source for current descriptions.

```
DIR=/tmp/$USER-nns-test/ STEPS='1' ./nns_dev_testnet.sh small02 1a2d86e9d66d93c4a9a9a147774577c377ce0c66
```

#### Within step 1, run only substeps 3 and 4 of nns_state_deployment.sh.
```
DIR=/tmp/$USER-nns-test/ STEPS='1' DEPLOYMENT_STEPS='[34]' ./nns_dev_testnet.sh small02 1a2d86e9d66d93c4a9a9a147774577c377ce0c66
```

### Interacting afterwards

Variables needed to interact with the testnet are captured in the directory used during the script's operation.  

These variables are captured to files in the `DIR` (or a temporary directory) which is printed at the end of the script.

Sourcing those files into your current directory will set environment variables that make interacting with the testnet
more convenient (so you do not need to specify NNS_URL or NEURON_ID when running many of the scripts).

To see what variables are set, look at the last lines in `../nns_state_deployment.sh` and `./nns_dev_testnet.sh`, or
investigate the output of the scripts.

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
to be the $SUBNET_URL (found in `$DIR/output_vars_nns_dev_testnet.sh`), as the $NNS_URL points at the NNS replica and 
will not route your requests to the correct subnet where the wallet canister lives.  

An example is `sns deploy`, which has to send cycles with the call, and therefore needs to use the wallet canister.  
That particular call also requires `--wallet-canister-override $WALLET_CANISTER` in order to specify the correct wallet.  
```
sns deploy --network $SUBNET_URL --wallet-canister-override $WALLET_CANISTER --init-config-file "<your_config_file>"
```

## NNS Canister Upgrade Testing Process

In order to test a canister upgrade, you will first need to spin up a testnet.  See [Spinning up a testnet](#spinning-up-a-testnet) above.

If you have a working testnet, start by sourcing variables into your local shell if you have not already done so.
`source /tmp/$USER-nns-test/output_vars_nns_dev_testnet.sh`

Next, we test the upgrade
`./test-canister-upgrade.sh <CANISTER_NAME> <TARGET_VERSION>`

`<CANISTER_NAME>` is the key of the canister in `rs/nns/canister_ids.json`.
`<TARGET_VERSION>` is the git hash of the version that has canisters available on the build system.

For example:
`./test-canister-upgrade.sh registry 1a2d86e9d66d93c4a9a9a147774577c377ce0c66`

The script will test upgrading the canister via proposal, and then upgrading it again via proposal.  It uses the gzipped
WASM as well as the un-gzipped WASM, as they will report different hashes in the running canister (allowing us to verify that the proposal succeeded.)

This is essential to ensuring that not only can we upgrade _to_ a particular version, but also _beyond_ that version.

## NNS Canister Upgrade Proposal Process

After you have verified your upgrade works with mainnet state (See [`NNS Canister Upgrade Testing Process`](#nns-canister-upgrade-testing-process)), 
you will prepare an upgrade proposal and submit it.

This process will be done on a machine that has an HSM key available.

First, run 
`./prepare-nns-upgrade-proposal-text.sh  <CANISTER_NAME> <TARGET_VERSION> <PROPOSAL_FILE>`

`PREVIOUS_COMMIT` can be optionally added as an environment variable if the canister in question does not have its currently  
 deployed commit as canister metadata. 

For example:
`./prepare-nns-upgrade-proposal-text.sh registry d2d9d63309cf568e3b2c2a0bc366b6850b044792 /tmp/upgrade_registry.md`

Next, you will need to open the file, and edit the section with `TODO ADD FEATURE NOTES` in it, and add a list of features
to be deployed.  These can be determined by looking at the list of commits generated in the proposal.

Finally, after inspecting the proposal, run 
`./submit-mainnet-nns-upgrade-proposal.sh <PROPOSAL_FILE> <YOUR_NEURON_ID>`

In this case, it is the neuron id associated with your HSM key (which must be plugged into your computer).

For example:
`./submit-mainnet-nns-upgrade-proposal.sh /tmp/upgrade_registry.md 123`

This script will read the proposal and validate the following:
1. The proposed canister ID is consistent with the human readable canister name in the title.
2. The hash in the proposal matches the hash of the WASM generated for that git version.
3. There are no TODO items left in the proposal text.

If these items validate, it will output the text of the proposal as well as generate the command for review.

It will ask for your HSM pin, and it will read out the command it is going to execute before executing it, requiring
confirmation by typing "yes" when asked if you want to proceed.


## Getting test coverage data with `get_test_coverage.sh`

This tool uses [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)
to generate coverage reports for the specified canister.

### Pre-requisites

- cargo-llvm-cov: see [installation instructions](https://github.com/taiki-e/cargo-llvm-cov#installation)

### Usage

```
get_test_coverage.sh <ns-instance> <canister-name>
```

For example, to get coverage of SNS governace canister run

```
get_test_coverage.sh sns governance
```
