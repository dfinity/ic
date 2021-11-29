# How to audit the state of NNS canisters

This directory contains a tool aimed at auditing the state of NNS canisters immediately after bootstrap.

## Upgrade NNS canisters

To force NNS canisters to write stable memory, they need to be upgraded.
See `launch/upgrade_nns_canister.sh`.

## Fetch canister states

Use the replica dashboard on an NNS replica to locate the canister state root path.
Click the arrow to expand the debug info for any NNS canister and search for `canister_root`.
Fetch the directory called `tip/canister_states` to a location reachable from the tool -- e.g., using `rsync` if this is on a remote replica.
See the following screenshot as an example:

![Screenshot](screenshot-canister-state-path.png?raw=true "Screenshot")


## Decode stable memories

Run:
`cargo run  --bin ic-nns-inspector -- <path_to_canister_state_dir> <path_to_desired_output_dir>`

This will create various files in the desired output directory that can be audited.

## Diff with the initial state

The most important part of the audit is to verify that the governance proto corresponds matches the desired initial state.
"Matches" here does not mean "is equal to" --- in particular, more proposals and recent ballots will appear in the stable memory than in the initial state.
Therefore "matches" should be understood as "differs in expected ways".

Here is an example command line for that.
Assuming that desired initial state is `../testnet/env/bootstrap/initial-governance.pb` and that the output directory is `~/stable`, one can run:

```
protoc \
  -I nns/governance/proto \
  -I nns/common/proto \
  -I types/base_types/proto \
  -I rosetta-api/ledger_canister/proto \
  nns/governance/proto/ic_nns_governance/pb/v1/governance.proto \
  --decode ic_nns_governance.pb.v1.Governance \
  < ../testnet/env/bootstrap/initial-governance.pb \
  > ~/stable/initial-governance-frompb.textproto 
```

then:
```
meld  ~/stable/governance_stable_memory.textproto ~/stable/initial-governance-frompb.textproto 
```

`meld` is a graphical diff viewer.
Others can be used, according to preference.

In case the `initial-governance.pb` was generated from  `.textproto`, it is tempting to skip the first step and simply compare `governance_stable_memory.textproto` with that.
Alas, this leads to poor result, as the textproto representation is not unique (e.g., there are several ways to escape in bytes arrays).
Regenerating the textproto from the pb will minimize spurious diffs.
