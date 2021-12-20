# Replay Tool manual

The replay tool is to help recover a broken subnet by replaying past blocks
and create a checkpoint of the latest state, which can then be used to
create recovery `CatchUpPackage`.

This is a vital step in the subnet recovery process.

It is very important, that the version of `ic-replay` you run corresponds to the version of the replica, i.e. is build from the same commit.

The `ic.json5` contains the IC configuration data that the replay tool will use.
Usually, in order to use the replay tool, changes to this file have to be made. This is because the `ic.json5` is configured to be run on a replica node and the replay tool is usually not used directly on that node but on a local copy of the state instead.

After copying the `/var/ic/data` directory into your local workspace, the following keys in the `ic.json5` file have to be set accordingly:

```json
registry.local_store: "./data/ic_registry_local_store/"
state_manager.state_root: "./data/ic_state"
artifact_pool.consensus_pool_path: "./data/ic_consensus_pool"
transport.node_ip: "127.0.0.1"
http_handler.listen_addr: "127.0.0.1:8080"
```

The tool is then invoked as follows:

```bash
ic-replay ic.json5 --subnet-id <SUBNET-ID> > replay_output.txt
```

This will recompute the state from the latest checkpoint to the current height, and then create a checkpoint there.
It will also output the latest height and state hash.
This Information is important for the generating a recovery cup and should be stored.

Now the data in the `data` directory can be copied back on the replica.


