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

## Replicate mainnet state in a dynamic testnet

An overview of this procedure

  1. Deploy a `recovered_mainnet_nns` dynamic testnet using `ict`.

  2. `source` shell script written by the previous step containing environment variable exports.

  4. Start using the testnet containing real data. For example, we use this to
     do [upgrade testing](#upgrade-testing) as part of our release procedure.

### Prerequisites

`dfx`. It can be installed like so:

```bash
sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"
```

`dfx` might get installed somewhere not on your `PATH` (e.g. `~/bin`). If so, you'll need to add it, e.g.

```bash
PATH=$PATH:$HOME/bin
```

### How to deploy a `recovered_mainnet_nns` dynamic testnet?

For best performance, run the following from a host in the `zh1` DC inside the root of the `ic` repo (note that this command is expected to take 10-15 min until the testnet is deployed):

```bash
gitlab-ci/container/container-run.sh

rm -rf test_tmpdir; \
  ict testnet create recovered_mainnet_nns \
    --lifetime-mins 120 \
    --set-required-host-features=dc=zh1 \
    --verbose \
    -- --test_tmpdir=test_tmpdir
```

`--lifetime-mins` specifies how long your testnet will be online. Make sure that it's long enough to complete your testing.

`--set-required-host-features=dc=zh1` ensures the testnet will be created in the `zh1` DC which speeds up the deployment. This is because the program needs to download the NNS state backup from the backup pod hosted in `zh1` and upload it from the test driver, running in `zh1`, to the IC deployed in `zh1`.

`-- --test_tmpdir=test_tmpdir` makes sure all the artifacts produced by the test driver are accessible on the filesystem in directory `test_tmpdir` which we need later on.

### Interacting Afterwards

To interact with the NNS Dapp search for a log line containing `NNS Dapp` like the following and follow the link:
```
2023-09-05 14:24:15.459 INFO[setup:rs/tests/nns/ic_mainnet_nns_recovery/src/lib.rs:293:0] NNS Dapp: https://qoctq-giaaa-aaaaa-aaaea-cai.ic0.farm.dfinity.systems
```
Not everything will work since signing in to the NNS dapp will redirect to the mainnet II (`https://identity.internetcomputer.org/`) instead of using a testnet-local II. This could be fixed later.

To interact with the testnet using the shell scripts in this directory certain environment variable are required to be defined. The test driver, launched in the previous step, will write a shell script `set_testnet_env_variables.sh` to `test_tmpdir` setting the required variables. This script can be sourced in your current shell. Just wait for a log line like the following:

```
2023-09-05 11:12:45.704 INFO[setup:rs/tests/nns/ic_mainnet_nns_recovery/src/lib.rs:616:0] source "/ic/test_tmpdir/_tmp/c689987f6ae05176e3097f73827ab180/setup/set_testnet_env_variables.sh"
```

Then go into another container again and source that script:

```
gitlab-ci/container/container-run.sh

source "/ic/test_tmpdir/_tmp/c689987f6ae05176e3097f73827ab180/setup/set_testnet_env_variables.sh"
```

Once you have those definitions, the following commands become possible:

```
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
./testnet/tools/nns-tools/upgrade-canister-to-working-tree.sh governance
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

<a name="upgrade-testing"></a>
## NNS Canister Upgrade Testing Process

This is usually done as one of the steps in the [NNS release process][1].

[1]: https://www.notion.so/Releasing-a-NNS-Canister-6d176f60478c4236a1af5f14462e73fc

In order to test a canister upgrade, you will first need to spin up a testnet.  See [Spinning up a testnet](#spinning-up-a-testnet) above.

If you have a working testnet, start by [sourcing variables into your local shell](#interacting-afterwards) if you have not already done so.

Next, we test the upgrade
```bash
./testnet/tools/nns-tools/test-canister-upgrade.sh <CANISTER_NAME> <TARGET_VERSION>
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
./testnet/tools/nns-tools/test-canister-upgrade.sh registry 1a2d86e9d66d93c4a9a9a147774577c377ce0c66
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
./testnet/tools/nns-tools/prepare-nns-upgrade-proposal-text.sh  <CANISTER_NAME> <TARGET_VERSION> <OUTPUT_PROPOSAL_FILE>
```

`PREVIOUS_COMMIT` can be optionally added as an environment variable if the canister in question does not have its currently
 deployed commit as canister metadata.

For example:

```bash
./testnet/tools/nns-tools/prepare-nns-upgrade-proposal-text.sh \
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
./testnet/tools/nns-tools/submit-mainnet-nns-upgrade-proposal.sh <PROPOSAL_FILE> <YOUR_NEURON_ID>
```

In this case, it is the neuron id associated with your HSM key.

For example:

```bash
./testnet/tools/nns-tools/submit-mainnet-nns-upgrade-proposal.sh /tmp/upgrade_registry.md 123
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

## Troubleshooting `nns_dev_testnet.sh`

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

### Crash on "2. Deploy an IC to the testnet."

Look at the end of the indicated log. If you see

```
EXIT received, killing all jobs
```

it might help if you try on another testnet.

### Password prompt on "2. Step 2: Create subnet from the unassigned nodes"

You may be prompted for a password. E.g.

```
admin@2607:f6f0:3004:1:5000:31ff:fe30:eabd's password:
```

At this point, the script is just waiting for something to happen. If you wait
long enough, it will probably succeed. To get past this check, do `Ctrl-C` to
break out of the script. Then, run the command again, except, prepend
`STEPS=[3-7] ` to it. This will forcibly move onto the next step. This is safe
to do assuming that the thing the script was waiting for actually succeed, which
it usually does after enough time has passed. TODO: How much time is needed?

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
