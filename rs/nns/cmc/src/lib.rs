use candid::{CandidType, Nat};
// TODO(EXC-1687): remove temporary alias `Ic00CanisterSettingsArgs`.
use ic_management_canister_types::{
    BoundedControllers, CanisterSettingsArgs as Ic00CanisterSettingsArgs, LogVisibilityV2,
};
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_types::{CanisterId, Cycles, PrincipalId, SubnetId};
use ic_xrc_types::ExchangeRate;
use icp_ledger::{
    AccountIdentifier, BlockIndex, Memo, SendArgs, Subaccount, Tokens, DEFAULT_TRANSFER_FEE,
};
use icrc_ledger_types::icrc1::account::Account;
use serde::{Deserialize, Serialize};

pub const DEFAULT_CYCLES_PER_XDR: u128 = 1_000_000_000_000u128; // 1T cycles = 1 XDR

pub const PERMYRIAD_DECIMAL_PLACES: u32 = 4;

pub const CREATE_CANISTER_REFUND_FEE: Tokens = Tokens::from_e8s(DEFAULT_TRANSFER_FEE.get_e8s() * 4);
pub const TOP_UP_CANISTER_REFUND_FEE: Tokens = Tokens::from_e8s(DEFAULT_TRANSFER_FEE.get_e8s() * 2);
pub const MINT_CYCLES_REFUND_FEE: Tokens = Tokens::from_e8s(DEFAULT_TRANSFER_FEE.get_e8s() * 2);

/// Cycles penalty charged for sending bad requests that incur a lot of work.
pub const BAD_REQUEST_CYCLES_PENALTY: u128 = 100_000_000; // TODO(SDK-1248) revisit fair pricing. Currently costs significantly more than an update call

pub const DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS: u64 = 1_620_633_600; // 10 May 2021 10:00:00 AM CEST
pub const DEFAULT_XDR_PERMYRIAD_PER_ICP_CONVERSION_RATE: u64 = 1_000_000; // 1 ICP = 100 XDR

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum ExchangeRateCanister {
    /// Enables the exchange rate canister with the given canister ID.
    Set(CanisterId),
    /// Disable the exchange rate canister.
    Unset,
}

impl ExchangeRateCanister {
    pub fn extract_exchange_rate_canister_id(&self) -> Option<CanisterId> {
        match self {
            ExchangeRateCanister::Set(exchange_rate_canister_id) => {
                Some(*exchange_rate_canister_id)
            }
            ExchangeRateCanister::Unset => None,
        }
    }
}
#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct CyclesCanisterInitPayload {
    pub ledger_canister_id: Option<CanisterId>,
    pub governance_canister_id: Option<CanisterId>,
    pub minting_account_id: Option<AccountIdentifier>,
    pub last_purged_notification: Option<BlockIndex>,
    pub exchange_rate_canister: Option<ExchangeRateCanister>,
    pub cycles_ledger_canister_id: Option<CanisterId>,
}

/// Argument taken by top up notification endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct NotifyTopUp {
    pub block_index: BlockIndex,
    pub canister_id: CanisterId,
}

// TODO(EXC-1670): remove after migration to `LogVisibilityV2`.
/// Log visibility for a canister.
/// ```text
/// variant {
///    controllers;
///    public;
/// }
/// ```
#[derive(Default, Clone, CandidType, Deserialize, Debug, PartialEq, Eq)]
pub enum LogVisibility {
    #[default]
    #[serde(rename = "controllers")]
    Controllers = 1,
    #[serde(rename = "public")]
    Public = 2,
}

impl From<LogVisibility> for LogVisibilityV2 {
    fn from(log_visibility: LogVisibility) -> Self {
        match log_visibility {
            LogVisibility::Controllers => Self::Controllers,
            LogVisibility::Public => Self::Public,
        }
    }
}

impl From<LogVisibilityV2> for LogVisibility {
    fn from(log_visibility: LogVisibilityV2) -> Self {
        match log_visibility {
            LogVisibilityV2::Controllers => Self::Controllers,
            LogVisibilityV2::Public => Self::Public,
            LogVisibilityV2::AllowedViewers(_) => Self::default(),
        }
    }
}

// TODO(EXC-1687): remove temporary copy of management canister types.
// It was added to overcome dependency on `LogVisibility` while
// management canister already migrated to `LogVisibilityV2`.
/// Struct used for encoding/decoding
/// `(record {
///     controllers: opt vec principal;
///     compute_allocation: opt nat;
///     memory_allocation: opt nat;
///     freezing_threshold: opt nat;
///     reserved_cycles_limit: opt nat;
///     log_visibility : opt log_visibility;
///     wasm_memory_limit: opt nat;
///     wasm_memory_threshold: opt nat;
/// })`
#[derive(Default, Clone, CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct CanisterSettingsArgs {
    pub controllers: Option<BoundedControllers>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
    pub reserved_cycles_limit: Option<candid::Nat>,
    pub log_visibility: Option<LogVisibility>,
    pub wasm_memory_limit: Option<candid::Nat>,
    pub wasm_memory_threshold: Option<candid::Nat>,
}

impl From<CanisterSettingsArgs> for Ic00CanisterSettingsArgs {
    fn from(settings: CanisterSettingsArgs) -> Self {
        Ic00CanisterSettingsArgs {
            controllers: settings.controllers,
            compute_allocation: settings.compute_allocation,
            memory_allocation: settings.memory_allocation,
            freezing_threshold: settings.freezing_threshold,
            reserved_cycles_limit: settings.reserved_cycles_limit,
            log_visibility: settings.log_visibility.map(LogVisibilityV2::from),
            wasm_memory_limit: settings.wasm_memory_limit,
            wasm_memory_threshold: settings.wasm_memory_threshold,
        }
    }
}

impl From<Ic00CanisterSettingsArgs> for CanisterSettingsArgs {
    fn from(settings: Ic00CanisterSettingsArgs) -> Self {
        CanisterSettingsArgs {
            controllers: settings.controllers,
            compute_allocation: settings.compute_allocation,
            memory_allocation: settings.memory_allocation,
            freezing_threshold: settings.freezing_threshold,
            reserved_cycles_limit: settings.reserved_cycles_limit,
            log_visibility: settings.log_visibility.map(LogVisibility::from),
            wasm_memory_limit: settings.wasm_memory_limit,
            wasm_memory_threshold: settings.wasm_memory_threshold,
        }
    }
}

/// Argument taken by create canister notification endpoint
#[derive(Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct NotifyCreateCanister {
    pub block_index: BlockIndex,

    /// If this not set to the caller's PrincipalId, notify_create_canister
    /// returns Err.
    ///
    /// Thus, notify_create_canister cannot be called on behalf of another
    /// principal. This might be surprising, but it is intentional.
    ///
    /// If controllers is not set in settings, controllers will be just
    /// [controller]. (Without this "default" behavior, the controller of the
    /// canister would be the Cycles Minting Canister itself.)
    pub controller: PrincipalId,

    #[deprecated(note = "use subnet_selection instead")]
    pub subnet_type: Option<String>,
    pub subnet_selection: Option<SubnetSelection>,

    pub settings: Option<CanisterSettingsArgs>,
}

/// Error for notify endpoints
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub enum NotifyError {
    Refunded {
        reason: String,
        block_index: Option<BlockIndex>,
    },
    InvalidTransaction(String),
    TransactionTooOld(BlockIndex),
    Processing,
    Other {
        error_code: u64,
        error_message: String,
    },
}

/// Argument taken by create_canister endpoint
#[derive(Default, Debug, Clone, CandidType, Deserialize, PartialEq, Eq)]
pub struct CreateCanister {
    #[deprecated(note = "use subnet_selection instead")]
    pub subnet_type: Option<String>,
    pub subnet_selection: Option<SubnetSelection>,
    pub settings: Option<CanisterSettingsArgs>,
}

/// Error for create_canister endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum CreateCanisterError {
    Refunded {
        refund_amount: u128,
        create_error: String,
    },
}

/// Options to select subnets when creating a canister
#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub enum SubnetSelection {
    /// Choose a random subnet that satisfies the specified properties
    Filter(SubnetFilter),
    /// Choose a specific subnet
    Subnet { subnet: SubnetId },
}

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct SubnetFilter {
    pub subnet_type: Option<String>,
}
pub enum NotifyErrorCode {
    /// An internal error in the cycles minting canister (e.g., inconsistent state).
    /// That should never happen.
    Internal = 1,
    /// The cycles minting canister failed to fetch block from ledger.
    FailedToFetchBlock = 2,
    /// The cycles minting canister failed to execute the refund transaction.
    RefundFailed = 3,
    /// The subnet selection parameters are set in an invalid way.
    BadSubnetSelection = 4,
    /// The caller is not allowed to perform the operation.
    Unauthorized = 5,
    /// Deposit memo field is too long.
    DepositMemoTooLong = 6,
}

impl NotifyError {
    /// Returns false if this error is permanent and should not be retried.
    pub fn is_retriable(&self) -> bool {
        !matches!(self, Self::Refunded { .. })
    }
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refunded {
                reason,
                block_index: Some(b),
            } => write!(f, "The payment was refunded in block {}: {}", b, reason),
            Self::Refunded {
                reason,
                block_index: None,
            } => write!(f, "The payment was refunded: {}", reason),
            Self::InvalidTransaction(err) => write!(f, "Failed to verify transaction: {}", err),
            Self::TransactionTooOld(bh) => write!(
                f,
                "The payment is too old, you cannot notify blocks older than block {}",
                bh
            ),
            Self::Processing => {
                write!(f, "Another notification of this transaction is in progress")
            }
            Self::Other {
                error_code,
                error_message,
            } => write!(
                f,
                "Notification failed with code {}: {}",
                error_code, error_message
            ),
        }
    }
}

pub type NotifyMintCyclesResult = Result<NotifyMintCyclesSuccess, NotifyError>;

/// Argument taken by `notify_mint_cycles` endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct NotifyMintCyclesArg {
    pub block_index: BlockIndex,
    pub to_subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount>,
    pub deposit_memo: Option<Vec<u8>>,
}

/// Result of `notify_mint_cycles` in case of success
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct NotifyMintCyclesSuccess {
    /// Cycles ledger block index of deposit
    pub block_index: icrc_ledger_types::icrc1::transfer::BlockIndex,
    /// Amount of cycles that were minted and deposited to the cycles ledger
    pub minted: Nat,
    /// New balance of the cycles ledger account
    pub balance: Nat,
}

/// Argument taken by the cycles ledger's `deposit` endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct CyclesLedgerDepositArgs {
    pub to: Account,
    pub memo: Option<Vec<u8>>,
}

/// Result of the cycles ledger's `deposit` endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct CyclesLedgerDepositResult {
    pub balance: Nat,
    pub block_index: Nat,
}

pub const MEMO_CREATE_CANISTER: Memo = Memo(0x41455243); // == 'CREA'
pub const MEMO_TOP_UP_CANISTER: Memo = Memo(0x50555054); // == 'TPUP'
pub const MEMO_MINT_CYCLES: Memo = Memo(0x544e494d); // == 'MINT'

pub fn create_canister_txn(
    amount: Tokens,
    from_subaccount: Option<Subaccount>,
    cycles_canister_id: &CanisterId,
    creator_principal_id: &PrincipalId,
) -> (SendArgs, Subaccount) {
    let sub_account = creator_principal_id.into();
    let send_args = SendArgs {
        memo: MEMO_CREATE_CANISTER,
        amount,
        fee: DEFAULT_TRANSFER_FEE,
        from_subaccount,
        to: AccountIdentifier::new(*cycles_canister_id.get_ref(), Some(sub_account)),
        created_at_time: None,
    };
    (send_args, sub_account)
}

pub fn top_up_canister_txn(
    amount: Tokens,
    from_subaccount: Option<Subaccount>,
    cycles_canister_id: &CanisterId,
    target_canister_id: &CanisterId,
) -> (SendArgs, Subaccount) {
    let sub_account = target_canister_id.into();
    let send_args = SendArgs {
        memo: MEMO_TOP_UP_CANISTER,
        amount,
        fee: DEFAULT_TRANSFER_FEE,
        from_subaccount,
        to: AccountIdentifier::new(*cycles_canister_id.get_ref(), Some(sub_account)),
        created_at_time: None,
    };
    (send_args, sub_account)
}

/// The result of create_canister transaction notification. In case of
/// an error, contains the index of the refund block.
pub type CreateCanisterResult = Result<CanisterId, (String, Option<BlockIndex>)>;

/// The result of top_up_canister transaction notification. In case of
/// an error, contains the index of the refund block.
pub type TopUpCanisterResult = Result<(), (String, Option<BlockIndex>)>;

pub struct TokensToCycles {
    /// Number of 1/10,000ths of XDR that 1 ICP is worth.
    pub xdr_permyriad_per_icp: u64,
    /// Number of cycles that 1 XDR is worth.
    pub cycles_per_xdr: Cycles,
}

impl TokensToCycles {
    pub fn to_cycles(&self, icpts: Tokens) -> Cycles {
        Cycles::new(
            icpts.get_e8s() as u128
                * self.xdr_permyriad_per_icp as u128
                * self.cycles_per_xdr.get()
                / (icp_ledger::TOKEN_SUBDIVIDABLE_BY as u128 * 10_000),
        )
    }
}

/// Argument taken by the set_authorized_subnetwork_list endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct SetAuthorizedSubnetworkListArgs {
    pub who: Option<PrincipalId>,
    pub subnets: Vec<SubnetId>,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct RemoveSubnetFromAuthorizedSubnetListArgs {
    pub subnet: SubnetId,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub enum UpdateSubnetTypeArgs {
    Add(String),
    Remove(String),
}

/// Errors that can happen when attempting to update an available subnet type.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub enum UpdateSubnetTypeError {
    Duplicate(String),
    TypeDoesNotExist(String),
    TypeHasAssignedSubnets((String, Vec<SubnetId>)),
}

impl std::fmt::Display for UpdateSubnetTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicate(subnet_type) => {
                write!(f, "Cannot add duplicate subnet type {}.", subnet_type)
            }
            Self::TypeDoesNotExist(subnet_type) => {
                write!(
                    f,
                    "The subnet type provided {} does not exist and cannot be removed.",
                    subnet_type
                )
            }
            Self::TypeHasAssignedSubnets((subnet_type, subnet_ids)) => {
                write!(
                    f,
                    "The subnet type provided {} has the following assigned subnets {:?} and cannot be removed.",
                    subnet_type,
                    subnet_ids
                )
            }
        }
    }
}

/// The result to a call to `update_subnet_type`.
pub type UpdateSubnetTypeResult = Result<(), UpdateSubnetTypeError>;

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct SubnetListWithType {
    pub subnets: Vec<SubnetId>,
    pub subnet_type: String,
}

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub enum ChangeSubnetTypeAssignmentArgs {
    Add(SubnetListWithType),
    Remove(SubnetListWithType),
}

/// Errors that can happen when attempting to change the assignment of a list of
///  subnets to a subnet type.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub enum ChangeSubnetTypeAssignmentError {
    /// The provided type does not exist.
    TypeDoesNotExist(String),
    /// Some of the provided subnets are already assigned to another type.
    SubnetsAreAssigned(Vec<SubnetListWithType>),
    /// Some of the provided subnets are already in the authorized or default
    /// subnets list maintained by CMC and cannot be assigned a type.
    SubnetsAreAuthorized(Vec<SubnetId>),
    /// Some of the provided subnets that were submitted to be removed from a
    /// type are not currently assigned to the type.
    SubnetsAreNotAssigned(SubnetListWithType),
}

impl std::fmt::Display for ChangeSubnetTypeAssignmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeDoesNotExist(subnet_type) => {
                write!(
                    f,
                    "Cannot add subnets to the subnet type {} as this subnet type does not exist.",
                    subnet_type
                )
            }
            Self::SubnetsAreAssigned(subnets_with_type) => {
                write!(
                    f,
                    "Some of the provided subnets are already assigned to a type {:?}.",
                    subnets_with_type
                )
            }
            Self::SubnetsAreAuthorized(subnet_ids) => {
                write!(
                    f,
                    "The provided subnets {:?} are authorized for public access and cannot be assigned a type.",
                    subnet_ids
                )
            }
            Self::SubnetsAreNotAssigned(subnets_with_type) => {
                write!(
                    f,
                    "The provided subnets are not assigned to a type {:?}.",
                    subnets_with_type
                )
            }
        }
    }
}

/// The result to a call to `change_subnet_type_assignment`.
pub type ChangeSubnetTypeAssignmentResult = Result<(), ChangeSubnetTypeAssignmentError>;

#[derive(Serialize, Deserialize, CandidType, Clone, PartialEq, Eq, Debug, Default)]
pub struct SubnetTypesToSubnetsResponse {
    pub data: Vec<(String, Vec<SubnetId>)>,
}

#[derive(Serialize, Deserialize, CandidType, Clone, PartialEq, Eq, Debug, Default)]
pub struct IcpXdrConversionRate {
    /// The time for which the market data was queried, expressed in UNIX epoch
    /// time in seconds.
    pub timestamp_seconds: u64,
    /// The number of 10,000ths of IMF SDR (currency code XDR) that corresponds
    /// to 1 ICP. This value reflects the current market price of one ICP
    /// token. In other words, this value specifies the ICP/XDR conversion
    /// rate to four decimal places.
    pub xdr_permyriad_per_icp: u64,
}

impl From<ExchangeRate> for IcpXdrConversionRate {
    fn from(value: ExchangeRate) -> Self {
        // Convert rate to permyriad rate.
        let power_diff = PERMYRIAD_DECIMAL_PLACES.abs_diff(value.metadata.decimals);
        let operation: fn(u64, u64) -> u64 =
            match value.metadata.decimals.cmp(&PERMYRIAD_DECIMAL_PLACES) {
                std::cmp::Ordering::Greater => u64::saturating_div,
                std::cmp::Ordering::Less => u64::saturating_mul,
                std::cmp::Ordering::Equal => |rate, _| rate,
            };
        let xdr_permyriad_per_icp = operation(value.rate, 10u64.pow(power_diff));

        Self {
            timestamp_seconds: value.timestamp,
            xdr_permyriad_per_icp,
        }
    }
}

impl From<UpdateIcpXdrConversionRatePayload> for IcpXdrConversionRate {
    fn from(val: UpdateIcpXdrConversionRatePayload) -> Self {
        IcpXdrConversionRate {
            timestamp_seconds: val.timestamp_seconds,
            xdr_permyriad_per_icp: val.xdr_permyriad_per_icp,
        }
    }
}

impl From<&UpdateIcpXdrConversionRatePayload> for IcpXdrConversionRate {
    fn from(val: &UpdateIcpXdrConversionRatePayload) -> Self {
        IcpXdrConversionRate {
            timestamp_seconds: val.timestamp_seconds,
            xdr_permyriad_per_icp: val.xdr_permyriad_per_icp,
        }
    }
}

#[derive(Serialize, Deserialize, CandidType, Clone, PartialEq, Eq)]
pub struct IcpXdrConversionRateCertifiedResponse {
    pub data: IcpXdrConversionRate,
    pub hash_tree: Vec<u8>,
    pub certificate: Vec<u8>,
}

#[derive(Serialize, Deserialize, CandidType, Clone, PartialEq, Eq, Debug, Default)]
pub struct AuthorizedSubnetsResponse {
    pub data: Vec<(PrincipalId, Vec<SubnetId>)>,
}

#[cfg(test)]
mod tests {
    use ic_xrc_types::{Asset, AssetClass, ExchangeRateMetadata};

    use super::*;

    #[test]
    fn tokens_to_cycles() {
        assert_eq!(
            (TokensToCycles {
                xdr_permyriad_per_icp: 10_000,
                cycles_per_xdr: Cycles::new(1234)
            })
            .to_cycles(Tokens::new(1, 0).unwrap()),
            Cycles::new(1234)
        );

        assert_eq!(
            (TokensToCycles {
                xdr_permyriad_per_icp: 21_042,
                cycles_per_xdr: 123_456_789_123u128.into()
            })
            .to_cycles(Tokens::new(123, 0).unwrap()),
            31952666407731u128.into()
        );
    }

    fn new_exchange_rate(rate: u64, decimals: u32) -> ExchangeRate {
        ExchangeRate {
            base_asset: Asset {
                symbol: "ICP".into(),
                class: AssetClass::Cryptocurrency,
            },
            quote_asset: Asset {
                symbol: "CXDR".into(),
                class: AssetClass::FiatCurrency,
            },
            timestamp: 0,
            rate,
            metadata: ExchangeRateMetadata {
                decimals,
                base_asset_num_queried_sources: 0,
                base_asset_num_received_rates: 0,
                quote_asset_num_queried_sources: 0,
                quote_asset_num_received_rates: 0,
                standard_deviation: 0,
                forex_timestamp: None,
            },
        }
    }

    #[test]
    fn exchange_rate_to_conversion_rate() {
        let exchange_rate = new_exchange_rate(4_916_453_360, 9);
        let conversion_rate = IcpXdrConversionRate::from(exchange_rate);
        assert_eq!(conversion_rate.xdr_permyriad_per_icp, 49_164);

        let exchange_rate = new_exchange_rate(491, 2);
        let conversion_rate = IcpXdrConversionRate::from(exchange_rate);
        assert_eq!(conversion_rate.xdr_permyriad_per_icp, 49_100);

        let exchange_rate = new_exchange_rate(49_164, 4);
        let conversion_rate = IcpXdrConversionRate::from(exchange_rate);
        assert_eq!(conversion_rate.xdr_permyriad_per_icp, 49_164);
    }
}
