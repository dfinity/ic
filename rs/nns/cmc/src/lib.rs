use candid::CandidType;
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_types::{CanisterId, Cycles, PrincipalId, SubnetId};
use ledger_canister::{
    AccountIdentifier, BlockHeight, Memo, SendArgs, Subaccount, Tokens, DEFAULT_TRANSFER_FEE,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CYCLES_PER_XDR: u128 = 1_000_000_000_000u128; // 1T cycles = 1 XDR

pub const CREATE_CANISTER_REFUND_FEE: Tokens = Tokens::from_e8s(DEFAULT_TRANSFER_FEE.get_e8s() * 4);
pub const TOP_UP_CANISTER_REFUND_FEE: Tokens = Tokens::from_e8s(DEFAULT_TRANSFER_FEE.get_e8s() * 2);

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct CyclesCanisterInitPayload {
    pub ledger_canister_id: CanisterId,
    pub governance_canister_id: CanisterId,
    pub minting_account_id: Option<AccountIdentifier>,
    pub last_purged_notification: Option<BlockHeight>,
}

/// Argument taken by top up notification endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct NotifyTopUp {
    pub block_index: BlockHeight,
    pub canister_id: CanisterId,
}

/// Argument taken by create canister notification endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct NotifyCreateCanister {
    pub block_index: BlockHeight,
    pub controller: PrincipalId,
}

/// Error for notify endpoints
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub enum NotifyError {
    Refunded {
        reason: String,
        block_index: Option<BlockHeight>,
    },
    InvalidTransaction(String),
    TransactionTooOld(BlockHeight),
    Processing,
    Other {
        error_code: u64,
        error_message: String,
    },
}

pub enum NotifyErrorCode {
    /// An internal error in the cycles minting canister (e.g., inconsistent state).
    /// That should never happen.
    Internal = 1,
    /// The cycles minting canister failed to fetch block from ledger.
    FailedToFetchBlock = 2,
    /// The cycles minting canister failed to execute the refund transaction.
    RefundFailed = 3,
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

pub const MEMO_CREATE_CANISTER: Memo = Memo(0x41455243); // == 'CREA'
pub const MEMO_TOP_UP_CANISTER: Memo = Memo(0x50555054); // == 'TPUP'

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
pub type CreateCanisterResult = Result<CanisterId, (String, Option<BlockHeight>)>;

/// The result of top_up_canister transaction notification. In case of
/// an error, contains the index of the refund block.
pub type TopUpCanisterResult = Result<(), (String, Option<BlockHeight>)>;

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
                * self.cycles_per_xdr.get() as u128
                / (ledger_canister::TOKEN_SUBDIVIDABLE_BY as u128 * 10_000),
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

impl From<UpdateIcpXdrConversionRatePayload> for IcpXdrConversionRate {
    fn from(val: UpdateIcpXdrConversionRatePayload) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_to_cycles() {
        assert_eq!(
            (TokensToCycles {
                xdr_permyriad_per_icp: 10_000,
                cycles_per_xdr: 1234.into()
            })
            .to_cycles(Tokens::new(1, 0).unwrap()),
            1234.into()
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
}
