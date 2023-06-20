//! The ECDSA API.

use crate::api::call::{call, call_with_payment128, CallResult};
use candid::Principal;

mod types;
pub use types::*;

/// Return a SEC1 encoded ECDSA public key for the given canister using the given derivation path.
///
/// See [IC method `ecdsa_public_key`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-ecdsa_public_key).
pub async fn ecdsa_public_key(
    arg: EcdsaPublicKeyArgument,
) -> CallResult<(EcdsaPublicKeyResponse,)> {
    call(Principal::management_canister(), "ecdsa_public_key", (arg,)).await
}

/// Return a new ECDSA signature of the given message_hash that can be separately verified against a derived ECDSA public key.
///
/// See [IC method `sign_with_ecdsa`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-sign_with_ecdsa).
///
/// This call requires cycles payment. The required cycles varies according to the subnet size (number of nodes).
/// Check [Gas and cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost) for more details.
pub async fn sign_with_ecdsa(
    arg: SignWithEcdsaArgument,
    cycles: u128,
) -> CallResult<(SignWithEcdsaResponse,)> {
    call_with_payment128(
        Principal::management_canister(),
        "sign_with_ecdsa",
        (arg,),
        cycles,
    )
    .await
}
