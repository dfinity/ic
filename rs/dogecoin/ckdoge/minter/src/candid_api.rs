//! Candid types for the canister enpoints (arguments and return types)

use candid::CandidType;
use icrc_ledger_types::icrc1::account::Subaccount;
use serde::Deserialize;

/// The arguments of the [retrieve_btc_with_approval] endpoint.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RetrieveDogeWithApprovalArgs {
    /// Amount to retrieve in satoshi
    pub amount: u64,

    /// Address where to send dogecoins
    pub address: String,

    /// The subaccount to burn ckDOGE from.
    pub from_subaccount: Option<Subaccount>,
}

impl From<RetrieveDogeWithApprovalArgs>
    for ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalArgs
{
    fn from(args: RetrieveDogeWithApprovalArgs) -> Self {
        Self {
            address: args.address,
            amount: args.amount,
            from_subaccount: args.from_subaccount,
        }
    }
}
