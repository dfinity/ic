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

## NNS Upgrade "Dress Rehersal"

This test helps ensures that NNS canisters remain upgradeable (in particular,
there is no panic during pre-upgrade).

(We used do to upgrade testing using testnets, but this is much better. Use git
history to see what we used to do.)

```
# Run from the usual place.
ssh -A devenv
cd src/ic
./ci/container/container-run.sh

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
# Fill these in.
RC=FAKE
# In case you aren't familiar, this is bash array.
NNS_CANISTERS=(
)
# Similar to NNS_CANISTERS
SNS_CANISTERS=(
)
# Path to an empty dir where the proposal files will be saved.
PROPOSALS_DIR=/tmp/release-$(date --iso)

mkdir $PROPOSALS_DIR

# NNS:
for CANISTER in "${NNS_CANISTERS[@]}"
do
    ./rs/nervous_system/tools/release/prepare-nns-upgrade-proposal-text.sh \
        $CANISTER \
        $RC \
        > $PROPOSALS_DIR/nns-$CANISTER.md
done

# SNS:
for CANISTER in "${SNS_CANISTERS[@]}"
do
    ./rs/nervous_system/tools/release/prepare-publish-sns-wasm-proposal-text.sh \
        $CANISTER \
        $RC \
        $PROPOSALS_DIR/sns-$CANISTER.md # no `>`
done

ls $PROPOSALS_DIR
```

You may need to set the `PREVIOUS_COMMIT` environment variable. This is needed
in the unlikely case where the git commit ID is not recorded in the currently
running WASM.

It used to be that you had to fill in some TODOs, but we simplified somewhat
recently, and that is no longer required.

### Submit the Proposal(s)

Plug in your HSM key. Unplug your Ubikey.

Optionally, you can test that your security hardware is ready by running

```bash
pkcs11-tool --list-slots

# If you want to practice entering your password:
pkcs11-tool --login --test
```

Finally, run

```bash
# In addition to the following, we assume that you still have the environment
# variables from the previous section...

# e.g. for Daniel Wong, 51
SUBMITTING_NEURON_ID=51

# NNS:
for CANISTER in "${NNS_CANISTERS[@]}"
do
    ./rs/nervous_system/tools/release/submit-mainnet-nns-upgrade-proposal.sh \
        $PROPOSALS_DIR/nns-$CANISTER.md \
        $SUBMITTING_NEURON_ID
done

# SNS:
for CANISTER in "${SNS_CANISTERS[@]}"
do
    ./rs/nervous_system/tools/release/submit-mainnet-publish-sns-wasm-proposal.sh \
        $PROPOSALS_DIR/sns-$CANISTER.md \
        $SUBMITTING_NEURON_ID
done
```

You can look up your neuron ID [here in Notion][neuron-id]. For example, Daniel Wong has neuron ID 51.

[neuron-id]: https://www.notion.so/dfinityorg/3a1856c603704d51a6fcd2a57c98f92f?v=fc597afede904e499744f3528cad6682


The submission scripts validate your proposal texts. Specifically, it enforces
the following requirements:

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
