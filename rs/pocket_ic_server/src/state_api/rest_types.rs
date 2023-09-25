/// This module contains the types that connect the PocketIc Operations (defined in
/// pocket_ic_server::pocket_ic) and the REST-API, which needs serializable types.
///
/// PocketIc Operations are deliberately not used directly, because other (non-REST-)
/// interfaces may require different serialization strategies. Therefore, we cannot
/// simply #derive(Serialize) for the PocketIc Operation types: That would fix a
/// serialization strategy.
///
/// The non-operation request and response types are also defined in this module.
use serde::{Deserialize, Serialize};

// ================================================================================================================= //
// Intermediate PocketIc Operation types: Needed to define how an Operation type should be serialized

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawCanisterCall {
    // #[serde(with = "base64")]
    pub sender: Vec<u8>,
    // #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub method: String,
    // #[serde(with = "base64")]
    pub payload: Vec<u8>,
}
