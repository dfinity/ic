use candid::{CandidType, Deserialize, Principal};

pub type CanisterId = Principal;
pub type SubnetId = Principal;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterIdRecord {
    pub canister_id: CanisterId,
}

// ========================================================================= //
// Types associated with the IC management canister that are not specified,
// but nevertheless useful for PocketIC.
//
// TODO: These should be moved to a separate module in the public crate
// ic-management-canister-types

use ic_management_canister_types::{EcdsaKeyId, SchnorrKeyId};
use serde::Serialize;
use strum_macros::{Display, EnumCount, EnumIter, EnumString};

/// Methods exported by ic:00.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, EnumIter, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Ic00Method {
    CanisterStatus,
    CanisterInfo,
    CreateCanister,
    DeleteCanister,
    DepositCycles,
    HttpRequest,
    ECDSAPublicKey,
    InstallCode,
    InstallChunkedCode,
    RawRand,
    SetupInitialDKG,
    SignWithECDSA,
    StartCanister,
    StopCanister,
    UninstallCode,
    UpdateSettings,
    ComputeInitialIDkgDealings,
    ReshareChainKey,

    // Schnorr interface.
    SchnorrPublicKey,
    SignWithSchnorr,

    // VetKd interface.
    #[strum(serialize = "vetkd_public_key")]
    VetKdPublicKey,
    #[strum(serialize = "vetkd_derive_encrypted_key")]
    VetKdDeriveEncryptedKey,

    // Bitcoin Interface.
    BitcoinGetBalance,
    BitcoinGetUtxos,
    BitcoinGetBlockHeaders,
    BitcoinSendTransaction,
    BitcoinGetCurrentFeePercentiles,
    // Private APIs used exclusively by the bitcoin canisters.
    BitcoinSendTransactionInternal, // API for sending transactions to the network.
    BitcoinGetSuccessors,           // API for fetching blocks from the network.

    // Subnet information
    NodeMetricsHistory,
    SubnetInfo,

    FetchCanisterLogs,

    // These methods are only available on test IC instances where there is a
    // need to fabricate cycles without burning ICP first.
    ProvisionalCreateCanisterWithCycles,
    ProvisionalTopUpCanister,

    // Support for chunked uploading of Wasm modules.
    UploadChunk,
    StoredChunks,
    ClearChunkStore,

    // Support for canister snapshots.
    TakeCanisterSnapshot,
    LoadCanisterSnapshot,
    ListCanisterSnapshots,
    DeleteCanisterSnapshot,
}

/// Types of curves that can be used for threshold key derivation (vetKD).
/// ```text
/// (variant { bls12_381_g2; })
/// ```
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    CandidType,
    Deserialize,
    EnumIter,
    Serialize,
)]
pub enum VetKdCurve {
    #[serde(rename = "bls12_381_g2")]
    #[allow(non_camel_case_types)]
    Bls12_381_G2,
}

/// Unique identifier for a key that can be used for threshold key derivation
/// (vetKD). The name is just an identifier, but it may be used to convey
/// some information about the key (e.g. that the key is meant to be used for
/// testing purposes).
/// ```text
/// (record { curve: vetkd_curve; name: text})
/// ```
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub struct VetKdKeyId {
    pub curve: VetKdCurve,
    pub name: String,
}

/// Unique identifier for a key that can be used for one of the signature schemes
/// supported on the IC.
/// ```text
/// (variant { EcdsaKeyId; SchnorrKeyId })
/// ```
#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    CandidType,
    Deserialize,
    EnumCount,
    Serialize,
)]
pub enum MasterPublicKeyId {
    Ecdsa(EcdsaKeyId),
    Schnorr(SchnorrKeyId),
    VetKd(VetKdKeyId),
}

// canister logs

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterLogRecord {
    pub idx: u64,
    pub timestamp_nanos: u64,
    pub content: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct FetchCanisterLogsResult {
    pub canister_log_records: Vec<CanisterLogRecord>,
}

// more recent version of the public crate:
// TODO: remove
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithSchnorrArgs {
    pub key_id: SchnorrKeyId,
    pub derivation_path: Vec<Vec<u8>>,
    pub message: Vec<u8>,
    pub aux: Option<SignWithSchnorrAux>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum SignWithSchnorrAux {
    #[serde(rename = "bip341")]
    Bip341(SignWithBip341Aux),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithBip341Aux {
    pub merkle_root_hash: Vec<u8>,
}
