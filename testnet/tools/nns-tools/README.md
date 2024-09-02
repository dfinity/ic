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

## Upgrade Testing via Bazel

```
# Run from the usual place.
ssh -A devenv
cd src/ic
./gitlab-ci/container/container-run.sh

# Within the container.
bazel test \
    --test_env=SSH_AUTH_SOCK \
    --test_env=NNS_CANISTER_UPGRADE_SEQUENCE=all \
    --test_output=streamed \
    --test_arg=--nocapture \
    //rs/nns/integration_tests:upgrade_canisters_with_golden_nns_state
```

This takes about 5 min on my devenv.

(This is a new way of doing upgrade/release testing (as of May 2024). The old way is still
documented elsewhere in this README.)

One special requirement for this to work is access to zh1-pyr07. This can be
requested from the consensus team, e.g. Christian Müller.

If your devenv is not in zh1, this test will run much slower, because it
downloads a large file.

Other than that, the only thing non-standard about the above command are the two
`--test_env` flags. Let us explain:

* `SSH_AUTH_SOCK`: This copies the value of the `SSH_AUTH_SOCK` environment
  variable from the environment where you are running into bazel's sandbox where
  it runs the test.

* `NNS_CANISTER_UPGRADE_SEQUENCE=...`: Here, you need to supply either a comma
  separated list of NNS canister names (e.g. `governance,root`), or `all` (as
  shown in the example).

The other `--test_*` flags are not strictly _required_, but rather, highly
recommended. Together, their effect is that you can watch the progress of the
test. Whereas, by default, you would have to wait until the end to see test
output (if there is a failure). For tests that take a longer time to run (like
this one), live results is better.

### Upgrade arguments

Sometimes we prepare a canister release that requires a special upgrade argument. These can be defined per-canister in `NnsCanisterUpgrade::new`. To illustarte, we have the following code:

```
let module_arg = if nns_canister_name == "cycles-minting" {
    Encode!(
        &(Some(CyclesCanisterInitPayload {
            cycles_ledger_canister_id: Some(CYCLES_LEDGER_CANISTER_ID),
            ledger_canister_id: None,
            governance_canister_id: None,
            minting_account_id: None,
            last_purged_notification: None,
            exchange_rate_canister: None,
        }))
    )
    .unwrap()
} else {
    Encode!(&()).unwrap()
};
```

This special CMC upgrade argument was needed only once, but we keep it for illustration since it should be harmless.

_Why we needed this arg in the first place: The CMC can mint cycles and transfer them directly to the cycles ledger. The cycles ledger was (re)installed recently in [this proposal](https://dashboard.internetcomputer.org/proposal/130327). Since it is now available and under NNS control, we needed to provide the canister ID to the CMC to enable the interaction with the cycles ledger._

### Troubleshooting

* `Cannot mkdir: No space`: try to clean up some space, e.g., by running the following command:

  ```
  ./bazel/bazel_clean.sh
  ```

## Replicate mainnet state in a dynamic testnet

*Warning*: There is now a [new (May, 2024)/better way to do release/upgrade
testing][bazel-based-upgrade-testing].

[bazel-based-upgrade-testing]: #upgrade-testing-via-bazel

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

This takes a bit over 20 minutes to run.

```bash
# You might be able to use devenv instead, but I have had problems with that.
#
# `caffeinate` is not required, but highly recommended. This is because
# without it, if you walk away from your computer for a while, your ssh
# connection will be lost, and as a result, `recovered_mainnet_nns` will
# not be kept alive.
#
# Note that, instead of zh1-spm22, you can also SSH to your devenv VM
# but that will be a bit slower (~30 minutes).
caffeinate ssh -A zh1-spm22.zh1.dfinity.network

# Check out recent commit of the ic repo. It does not have to be the release candidate commit,
# because pre-built WASMs are used (downloaded from S3).
cd ic
git checkout master
git pull

# Optional. This is recommended in case you lose your ssh connection.
tmux -S release

./gitlab-ci/container/container-run.sh

TEST_TMPDIR="/tmp/$(whoami)/test_tmpdir"; \
echo "TEST_TMPDIR=$TEST_TMPDIR"; \
rm -rf "$TEST_TMPDIR"; \
    ict testnet create recovered_mainnet_nns \
        --lifetime-mins 1440 \
        --set-required-host-features=dc=zh1 \
        --verbose \
        -- \
        --test_tmpdir="$TEST_TMPDIR"
```

Let us explain some of the arguments used above:

* `--lifetime-mins` specifies how long your testnet will be online. Make sure that it's long enough
  to complete your testing.

* `--set-required-host-features=dc=zh1` ensures the testnet will be created in the `zh1` DC which
  speeds up the deployment. This is because the program needs to download the NNS state backup from
  the backup pod hosted in `zh1` and upload it from the test driver, running in `zh1`, to the IC
  deployed in `zh1`.

* `--test_tmpdir=/tmp/$(whoami)/test_tmpdir` makes sure all the artifacts produced by the test driver are
  accessible on the filesystem in directory `/tmp/$(whoami)/test_tmpdir` which we need later on.

Once `ict` finishes setting things up, it stays running in the foreground. At that point, you should
see (something like) this in green:

<!-- TODO: replace with image, in order to show color. -->
```
Congrats, testnet with Farm group=recovered_mainnet_nns--1695980832098 was deployed successfully!
```

You can properly dispose of the testnet by killing the `ict` process.

### Interacting Afterwards

To interact with the testnet using the shell scripts in this directory, you'll need to run
`set_testnet_env_variables.sh` deep within `/tmp/$(whoami)/test_tmpdir`. There is a helper function to do this for you:

```
./gitlab-ci/container/container-run.sh
# you probably don't need this if you're just going to use the SNS and NNS upgrade testing scripts
# as they call it for you. If that's your plan, just skip this step.
. ./testnet/tools/nns-tools/cmd.sh set_testnet_env_variables
```

Once you have those definitions, the following commands become possible:

```
dfx canister \
    --network $NNS_URL \
    call \
    --candid rs/nns/sns-wasm/canister/sns-wasm.did \
    qaa6y-5yaaa-aaaaa-aaafa-cai \
    get_sns_subnet_ids \
    '(record {})'

$IC_ADMIN --nns-url "$NNS_URL" get-topology
```

#### Making Calls Via the Wallet Canister

An example is `sns deploy`, which has to send cycles with the call, and therefore needs to use the
wallet canister. Running `sns deploy` has a couple other prerequisites:

1. `--wallet-canister-override $WALLET_CANISTER`
2. Coming up with a configuration file.

```bash
$SNS_CLI deploy \
    --network "$SUBNET_URL" \
    --wallet-canister-override "$WALLET_CANISTER" \
    --init-config-file "$CONFIG_FILE"
```

#### nns-dapp

To interact with the NNS Dapp, search for a log line containing `NNS Dapp` similar to this:

```
... NNS Dapp: https://qoctq-giaaa-aaaaa-aaaea-cai.ic0.farm.dfinity.systems
```

Not everything will work since signing in to the NNS dapp will redirect to the mainnet II
(`https://identity.internetcomputer.org/`) instead of using a testnet-local II. This could be fixed
later.

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

### Troubleshooting `ict testnet create recovered_mainnet_nns ...`

#### Unable to SSH to pyr07

```
'Could not setup SSH session to dev@zh1-pyr07.zh1.dfinity.network because: [Session(-18)] Username/PublicKey combination invalid!', rs/tests/nns/ic_mainnet_nns_recovery/src/lib.rs
```

This indicates trouble with ssh agent forwarding. There are a few things you can do (from within the
container) to diagnose this:

1. `ssh-add -l` This should list some identities.
2. `echo $SSH_AUTH_SOCK` This should print out `/ssh-agent`.
3. `ssh zh1-pyr07.zh1.dfinity.network` You should be able to ssh into `zh1-pyr07`.

On the other hand, this can also occur if your ssh-agent is holding > 1 identity. (IMHO, this is due
to a bug in the ssh2 library.) To get around that, try applying this patch:

```diff
diff --git a/rs/tests/nns/ic_mainnet_nns_recovery/src/lib.rs b/rs/tests/nns/ic_mainnet_nns_recovery/src/lib.rs
index eac116ade0..0f1b13121f 100644
--- a/rs/tests/nns/ic_mainnet_nns_recovery/src/lib.rs
+++ b/rs/tests/nns/ic_mainnet_nns_recovery/src/lib.rs
@@ -113,11 +113,14 @@ pub fn setup(env: TestEnv) {
         logger,
         "Setting up SSH session to {NNS_BACKUP_POD_USER}@{NNS_BACKUP_POD} ..."
     );
+
+    /*
     let _sess = get_ssh_session_to_backup_pod().unwrap_or_else(|e| {
         panic!(
             "Could not setup SSH session to {NNS_BACKUP_POD_USER}@{NNS_BACKUP_POD} because: {e:?}!",
         )
     });
+    */

     // The following ensures ic-replay and ic-recovery know where to get their required dependencies.
     let recovery_dir = env.get_dependency_path("rs/tests");
```

To apply this patch,

```
git apply -
```

Then, paste the patch into your terminal. Hit enter. Then, hit Ctrl-d (as in "dog"). Try `git diff`
to verify that the patch applied as show above.

#### Fail to Parse ic.json5

```
Failed to parse config from file './setup/recovery/working_dir/ic.json5': expected an object
```

Revert a problemmatic commit:

```
git revert --no-commit 3ba9857f19cf22b5da85e1268f914f58f66f3d3a
```

For more information on what's going on here, see [this Slack thread][revert-needed-slack-thread].

[revert-needed-slack-thread]: https://dfinity.slack.com/archives/C039M7YS6F6/p1695970993659729?thread_ts=1695938621.025989&cid=C039M7YS6F6

<a name="upgrade-testing"></a>
## NNS/SNS Canister Upgrade Testing Process

This is usually done as one of the steps in the [NNS release process][1].

[1]: https://www.notion.so/Releasing-a-NNS-Canister-6d176f60478c4236a1af5f14462e73fc

In order to test a canister upgrade, you will first need to spin up a testnet.  See [Spinning up a testnet](#spinning-up-a-testnet) above.

If you have a working testnet, start by [sourcing variables into your local shell](#interacting-afterwards) if you have not already done so.

Next, we test the upgrade
```bash
# NNS:
./testnet/tools/nns-tools/test-canister-upgrade.sh <CANISTER_NAME> <TARGET_VERSION>

# SNS:
# Test upgrading the specified SNS canisters from mainnet version to the
# specified version in every possible order
./testnet/tools/nns-tools/test-sns-canister-upgrades.sh <TARGET_VERSION> <CANISTER_NAME> (<CANISTER_NAME>...)
# Test deploying a new SNS with the specified canister versions
./testnet/tools/nns-tools/test-sns-canister-deployment.sh <TARGET_VERSION> <CANISTER_NAME> (<CANISTER_NAME>...)
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

## Troubleshooting

If you see:

```
NotAuthorized: Caller not authorized to propose
```

Your environment variables could be set from a previous run of recovered_mainnet_nns. In this case, exit and re-enter your shell to reset them. Rerunning `. ./testnet/tools/nns-tools/cmd.sh set_testnet_env_variables` will not help as that script tries not to overwrite variables you already have.

## NNS/SNS Canister Upgrade Proposal Process

This is usually done as one of the steps in the [NNS release process][1].

[1]: https://www.notion.so/Releasing-a-NNS-Canister-6d176f60478c4236a1af5f14462e73fc

The commands in this section require an HSM device. Thus, the commands here need to be run locally,
not on your devenv or zh1-spm22, as was done in previous sections.

At a high level, there are two sub-step here:

  1. Create a proposal text file (one for each canister).
  2. Make/submit the proposal.

### Creating the Proposal Text File

Generate a mostly pre-populated proposal text file:

```bash
# NNS:
./testnet/tools/nns-tools/prepare-nns-upgrade-proposal-text.sh \
    <CANISTER_NAME> \
    <TARGET_VERSION> \
    > <OUTPUT_PROPOSAL_FILE>

# SNS:
./testnet/tools/nns-tools/prepare-publish-sns-wasm-proposal-text.sh \
    <CANISTER_NAME> \
    <TARGET_VERSION> \
    <OUTPUT_PROPOSAL_FILE> # no `>`
```

For example:

```bash
./testnet/tools/nns-tools/prepare-nns-upgrade-proposal-text.sh \
    registry \
    d2d9d63309cf568e3b2c2a0bc366b6850b044792 \
    > /tmp/registry-upgrade-proposal-2023-09-29.md
```

You may need to set the `PREVIOUS_COMMIT` environment variable. This is needed in the unlikely case
where the git commit ID is not recorded in the currently running WASM.

Once the script has done its part, your job is then to fill in the TODO(s). Figuring out how to fill
those out is a matter of looking at the list of commits generated in the proposal.

### Submit the Proposal(s)

Plug in your HSM key. Unplug your Ubikey.

Optionally, you can test that your security hardware is ready by running

```bash
pkcs11-tool --login --test
```

Finally, run

```bash
# NNS:
./testnet/tools/nns-tools/submit-mainnet-nns-upgrade-proposal.sh \
    <PROPOSAL_FILE> \
    <YOUR_NEURON_ID>

# SNS:
./testnet/tools/nns-tools/submit-mainnet-publish-sns-wasm-proposal.sh \
    <PROPOSAL_FILE> \
    <YOUR_NEURON_ID>
```

You can look up your neuron ID [here in Notion][neuron-id]. For example, Daniel Wong has neuron ID 51.

[neuron-id]: https://www.notion.so/dfinityorg/3a1856c603704d51a6fcd2a57c98f92f?v=fc597afede904e499744f3528cad6682

For example:

```bash
./testnet/tools/nns-tools/submit-mainnet-nns-upgrade-proposal.sh \
    /tmp/registry-upgrade-proposal-2023-09-29.md \
    51
```

The script validates your proposal text. Specifically, it enforces the following requirements:

1. There are no TODO items left in the proposal text.

If your proposal text checks out, the script then prompts you for your HSM pin.

After that, it prints out the command it is about to execute, and ask you to confirm. To confirm,
type in "yes".

Once the proposal(s) have been made, take a note of the proposal ID (printed at the end).

You will need to notify people about this proposal so that they know to vote on it.
Jump back to the [release runbook in Notion][1].

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
