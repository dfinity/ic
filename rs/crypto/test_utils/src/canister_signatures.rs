//! Utilities for testing Internet Computer Canister Signatures (ICCSA).
use ic_types::CanisterId;
use std::convert::TryFrom;

pub fn canister_sig_pub_key_to_bytes(signing_canister_id: CanisterId, seed: &[u8]) -> Vec<u8> {
    let canister_id_principal_bytes = signing_canister_id.get_ref().as_slice();
    let mut buf = vec![];
    buf.push(u8::try_from(canister_id_principal_bytes.len()).expect("u8 too small"));
    buf.extend_from_slice(canister_id_principal_bytes);
    buf.extend_from_slice(seed);
    buf
}
