# ICP Ledger and Archive Upgrade Test Scripts

This directory contains a set of scripts useful to test the upgrade of the ICP Ledger canister or the ICP Archive canister. You need a testnet where you can run the tests. All the scripts must run from within [dev container](../../../ci/container/container-run.sh).

The main testing file is [`run_upgrade_test.sh`](./run_upgrade_test.sh) and be called as:

```bash
$ ./run_upgrade_test.sh <testnet> <commit_id> (archive|ledger)
```

For more info about the tests please refer to the [notion page](https://www.notion.so/dfinityorg/How-to-upgrade-the-ICP-ledger-on-a-testnet-798eb588363f46a080ea1110e34772d9?pvs=4).