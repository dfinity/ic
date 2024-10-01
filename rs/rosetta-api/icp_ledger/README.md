# Ledger

This package contains the implementation of the ICP ledger canister.

## Deploying locally

### From a release version

See [Ledger Local Setup](https://internetcomputer.org/docs/current/developer-docs/integrations/ledger/ledger-local-setup).

### From local code (ICP Ledger)

With a running local replica and minter and default accounts properly configures (as described in the [Ledger Local Setup](https://internetcomputer.org/docs/current/developer-docs/integrations/ledger/ledger-local-setup) guide), run:

```bash
# WARNING: The command below will stop and delete any canister running under id ryjl3-tyaaa-aaaaa-aaaba-cai
$ bazel run //rs/rosetta-api/icp_ledger/ledger:dfx_deploy
```

The above command will build an icp canister from your current code and deploy it to the local replica. You can then interact with it just as described in the guide above.

### Debugging

If you want to be able to see the logs coming from your local canister when running it in a local replica, start the replica with:

```bash
$ dfx start --clean --background -vv --log file --logfile /tmp/dfx.log
```
and follow the logs in `/tmp/dfx.log`