## ic-pub-key

The Internet Computer protocol offers a number of threshold signature schemes to
canisters running on the system. The public keys which are used to verify these
signatures are derived from a single master public key using a deterministic
scheme which includes the canister's identifier as well as any canister-provided
context data.

This derivation can be performed "online" by a canister using a query call, but
this is inconvenient in some usage scenarios. This crate offers an alternative,
namely fully *offline* key derivation.
