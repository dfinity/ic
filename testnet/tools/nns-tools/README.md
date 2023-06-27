# NNS Tools

A small collection of tools for testing NNS canisters and upgrades on testnets.

## Developing scripts / tools

Most functionality should be written in small self-contained functions that do not reference any global state.
This makes the entire library more composable and functions can be easily used in other contexts where the conventions
for naming are different, or conventions for what variables mean. 

To add documentation to a particular function so that it shows up in `./cmd.sh` output, Use the following structure and put
your function in a file inside of `./lib`.

```
##: my_useful_function
## Usage: $1 <PARAM1> <PARAM2> (<OPTTIONAL_PARAM1> <OPTIONAL_PARAM2>)
## My function does something very very useful
##   PARAM1: Param 1 description...
##   PARAM2: You get the idea...
##   OPTTIONAL_PARAM1: that you should document how to use parameters 
##   OPTTIONAL_PARAM2: if it is going to be exposed 
my_useful_function() {
 ...
}
```

## Spinning up a testnet

### Prerequisites

`dfx`. It can be installed like so:

```bash
sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"
```

`dfx` might get installed somewhere not on your `PATH` (e.g. `~/bin`). If so, you'll need to add it, e.g.

```bash
PATH=$PATH:$HOME/bin
```

Knowledge of testnets. Read [go/testnets](http://go/testnets) if you need to be brought up to speed.

You will need to pick a testnet that has a `hosts_unassigned.ini` file. To figure out which ones fit that description, use this
[query](https://sourcegraph.com/search?q=context:global+repo:dfinity/ic+f:hosts_unassigned.ini+f:%28small%7Cmedium%7Clarge%29&patternType=regexp&case=yes&sm=1&groupBy=repo).
E.g. currently, small01 has such a file.

### nns_dev_testnet.sh

This script creates a testnet with mainnet state using a stable shared identity and modifies it in a few ways for development purposes.
1. Adds an application subnet.
2. Sets CMC default subnet list to that application subnet.
3. Creates a cycles wallet for our shared principal on the application subnet.
4. Configures SNS-W to create SNS's on application subnet, and to respond to our principal's wallet.
5. Uploads the latest SNS Wasms into SNS-W canister

It then stores all the variables in a directory (which is output) so they can be easily referenced for
interaction with the subnet

Needs to be run on zh1-spm22.zh1.dfinity.network. (Ideally, we'd
be able to run this locally; implementing that is feasible, but
we haven't done it yet.)

### Example usage of nns_dev_testnet.sh

When running the testnet creation script, a temporary directory is created.  If you would like to use a particular directory
you can set `DIR` in your environment.  In our examples, we do this to make it easier to find the outputs from the 
scripts.

For more information, run `./nns_dev_testnet.sh` without arguments.

#### Run the entire script

```
DIR=/tmp/$USER-nns-test ./nns_dev_testnet.sh small02
```

#### Run only the full step 1 of the script.

Sometimes, during testnet setup or when developing the script, you may want to only run some parts.  To see the parts,
read the script source for current descriptions.

```
DIR=/tmp/$USER-nns-test STEPS='1' ./nns_dev_testnet.sh small02
```

#### Within step 1, run only sub-steps 3 and 4 of nns_state_deployment.sh.
```
DIR=/tmp/$USER-nns-test STEPS='1' DEPLOYMENT_STEPS='[34]' ./nns_dev_testnet.sh small02
```

### Interacting Afterward

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

## Running Your Latest and Greatest Changes

You can see what it would be like if we tried to upgrade a canister (e.g. NNS
governance) to whatever you have in your working copy. Assuming you have done
the above to load mainnet state into a testnet, you can try running whatever
code you have (even if it's not committed) by running one simple command:

```bash
# Assuming you have sourced the various *.sh files mentioned above,
# and you are currently in this directory,
canister=governance ./upgrade-canister-to-working-tree.sh "$(nns_canister_id "${canister}")"
```

If all goes well, you should see "Upgrade was successful." on the last line (or
something to that effect). Now, you can start hitting your shiny new
code. E.g. if you added a method, you would now be able to call it like so:

```bash
canister=governance dfx canister \
  --network "${NNS_URL}" \
  call \
  "$(nns_canister_id "${canister}")" \
  new_method \
  '(record {})'
```

## NNS Canister Upgrade Testing Process

This is usually done as one of the steps in the [NNS release process][1].

[1]: https://www.notion.so/Releasing-a-NNS-Canister-6d176f60478c4236a1af5f14462e73fc

In order to test a canister upgrade, you will first need to spin up a testnet.  See [Spinning up a testnet](#spinning-up-a-testnet) above.

If you have a working testnet, start by sourcing variables into your local shell if you have not already done so.
```bash
source /tmp/$USER-nns-test/output_vars_nns_dev_testnet.sh
````

Next, we test the upgrade
```bash
./test-canister-upgrade.sh <CANISTER_NAME> <TARGET_VERSION>
```

* `<CANISTER_NAME>` is the key of the canister in `rs/nns/canister_ids.json`.
* `<TARGET_VERSION>` is the git hash of the version that has canisters available
  on the build system. You can find a suitable value by looking at the
  [commits page](https://gitlab.com/dfinity-lab/public/ic/-/commits/master?ref_type=heads)
  in Gitlab. In one of the columns towards the right, you will see some red Xs
  and green checkmarks. If you click on the clipboard icon next to a green checkmark,
  you will copy a suitable value.

For example:

```bash
./test-canister-upgrade.sh registry 1a2d86e9d66d93c4a9a9a147774577c377ce0c66
```

The script will test upgrading the canister via proposal, and then upgrading it again via proposal.  It uses the gzipped
WASM as well as the un-gzipped WASM, as they will report different hashes in the running canister (allowing us to verify that the proposal succeeded.)

This is essential to ensuring that not only can we upgrade _to_ a particular version, but also _beyond_ that version.

## NNS Canister Upgrade Proposal Process

This is usually done as one of the steps in the [NNS release process][1].

[1]: https://www.notion.so/Releasing-a-NNS-Canister-6d176f60478c4236a1af5f14462e73fc

The commands in this section need to be run locally, not in zh1-spm22, like the commands
in other sections.

After you have verified your upgrade works with mainnet state
(See [`NNS Canister Upgrade Testing Process`](#nns-canister-upgrade-testing-process)), 
you will prepare an upgrade proposal (i.e. come up with a file containing proposal text) and make the proposal.

This process will be done on a machine that has an HSM key available.
(This is why these commands must be run locally.)

First, to begin writing a file with some pre-populated proposal text, run 

```bash
./prepare-nns-upgrade-proposal-text.sh  <CANISTER_NAME> <TARGET_VERSION> <OUTPUT_PROPOSAL_FILE>
```

`PREVIOUS_COMMIT` can be optionally added as an environment variable if the canister in question does not have its currently  
 deployed commit as canister metadata. 

For example:

```bash
./prepare-nns-upgrade-proposal-text.sh \
    registry \
    d2d9d63309cf568e3b2c2a0bc366b6850b044792 \
    /tmp/upgrade_registry.md
```

(Omitting the third argument would cause the text to be printed to stdout instead of writing the contents to the specified path.)

Next, you will need to open the file, and edit the section with `TODO ADD FEATURE NOTES` in it, and add a list of features
to be deployed.  These can be determined by looking at the list of commits generated in the proposal.

Plug in your HSM key. Unplug your Ubikey. Optionally, you can test that your security hardware is ready by running

```bash
pkcs11-tool --list-slots
```

Finally, run

```bash
./submit-mainnet-nns-upgrade-proposal.sh <PROPOSAL_FILE> <YOUR_NEURON_ID>
```

In this case, it is the neuron id associated with your HSM key.

For example:

```bash
./submit-mainnet-nns-upgrade-proposal.sh /tmp/upgrade_registry.md 123
```

This script will read the proposal and validate the following:
1. The proposed canister ID is consistent with the human-readable canister name in the title.
2. The hash in the proposal matches the hash of the WASM generated for that git version.
3. There are no TODO items left in the proposal text.

If these items validate, it will output the text of the proposal as well as generate the command for review.

It will ask for your HSM pin, and it will read out the command it is going to execute before executing it, requiring
confirmation by typing "yes" when asked if you want to proceed.

Once the proposal(s) have been made, make a note of the proposal ID (printed at the end).

You will need to notify people about this proposal so that they know to vote on it.
Jump back to the [release runbook in Notion][1].

## Troubleshooting `nns_dev-testnet.sh`

### Could not fetch catch up package

If you seem to be stuck on "6. Recover the NNS subnet to the first
unassigned node", check out the log mentioned at that step
(6_nns_recovery_log.txt). You may see many lines similar to the following:

```
Mar 21 00:11:30.904 INFO Try: 21. Could not fetch CUP: failed to get catch up package: Request failed for http://[2a00:fb01:400:42:5000:f9ff:fe05:faa0]:8080/_/catch_up_package: hyper::Error(Connect, ConnectError("tcp connect error", Os { code: 111, kind: ConnectionRefused, message: "Connection refused" }))
Mar 21 00:11:30.904 INFO Recovery CUP not yet present, retrying...
```

If so, try contacting someone on the Consensus team (E.g. Leo Eichhorn
and Christian Müller) on the #eng-testing Slack channel.
E.g. [here](https://dfinity.slack.com/archives/C018WHN6R2L/p1679358521278899).

A few failed attempts is not bad. Therefore, if you haven't been waiting
that long, no need to immediately call for backup. (You might want
to start drafting a plea for help while you are waiting.)

## Getting test coverage data with `get_test_coverage.sh`

This tool uses [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)
to generate coverage reports for the specified canister.

### Pre-requisites

- cargo-llvm-cov: see [installation instructions](https://github.com/taiki-e/cargo-llvm-cov#installation)

### Usage

```
get_test_coverage.sh <ns-instance> <canister-name>
```

For example, to get coverage of SNS governance canister run

```
get_test_coverage.sh sns governance
```
