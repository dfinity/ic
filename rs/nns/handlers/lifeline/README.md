# The `lifeline` Canister

The `lifeline` is a last line of defense against a misbehaving IC.

Being the controller of the `root` canister, `lifeline` allows its upgrade and thus the fixing of all NNS canisters should some common (e.g. library or codegen) flaw be present in any of the NNS canisters.

The controller of the `lifeline` canister is `root`, so upgrading of it is standard.

## Technology used

The `lifeline` canister is written in Motoko and uses an alternative technology than the other NNS canisters that are written in Rust and use libraries from that ecosystem. This allows for some degree of  “galvanic separation” of  technologies, such that the risk of inheriting some kind of common flaw from the compiler (and/or libraries) is reduced.

## Building

Even though this is a Motoko canister, there is a Rust wrapper for its wasm.
The wasm can be re-built by running `cargo build` from this directory, or running `cargo build -p lifeline` from anywhere in `rs/`.
This will re-generate file `gen/lifeline.wasm`, which is ignored from version control.

### (Re-)creating the `.did` file

_Note_: The `lifeline` canister's interface should be rather stable, think twice if you want to change it!

In case the user-facing interface of `lifeline` has changed, it makes sense to update the `lifeline.did` file. To perform that, following command can be run in the CLI
``` shell
env MOC_UNLOCK_PRIM=yesplease moc --idl -o lifeline.did lifeline.mo --actor-alias governance "rrkah-fqaaa-aaaaa-aaaaq-cai" --actor-alias root "rkp4c-7iaaa-aaaaa-aaaca-cai" --actor-idl .
```
The `--idl` option makes sure that the `.did` file is updated.

Before comitting the `.did` file, the `git diff` should be consulted, and the (for external usage) irrelevant changes backed out. Please note that the purely internal (callback) method `upgrade_root` should not appear in the `.did` file, and should be removed entirely (preferred) or (at least) commented out.

## How `lifeline` is built in `nix`

All the work happens in the Cargo build.
All that happens in `nix` to publish the canister is to copy the `lifeline.wasm` from `gen/` to the `bin/` output directory.
This is done in `rs/overrides.nix`.
