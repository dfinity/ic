# ic0

Internet Computer System API binding.

## What

`ic0` is simply a safe Rust translation of the System API as described in the [IC interface specification][1]. The unsafe direct imports can be found in the `ic0::sys` module.

## Update

`ic0` keeps in step with the IC interface specification. Particularly, `ic0` is directly generated from the [system API][1] in that repo.

When interface-spec releases a new version that modify [system API][1]:

1. replace `ic0.txt` in the root of this project;
2. copy any new function headers to `manual_safety_comments.txt`, and add a safety comment for the function;
3. execute `cargo run --example=ic0build`;

`src/sys.rs` should be updated.

[1]: https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-imports
