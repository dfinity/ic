use candid::{CandidType, Deserialize, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account,
};
use ic_icrc1_client_cdk::{CdkRuntime, ICRC1Client};

use crate::{
    guard::{retrieve_btc_guard, GuardError},
    state::{mutate_state, read_state, RetrieveBtcRequest},
};

use super::{
    get_btc_address::{hrp, init_ecdsa_public_key},
    get_withdrawal_account::compute_subaccount,
};

const MAX_CONCURRENT_PENDING_REQUESTS: usize = 100;

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct RetrieveBtcArgs {
    // amount to retrieve in satoshi
    pub amount: u64,

    // bitcoin fee to use
    pub fee: Option<u64>,

    // address where to send bitcoins
    pub address: String,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct RetrieveBtcOk {
    // the index of the burn block on the ckbtc ledger
    pub block_index: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub enum RetrieveBtcErr {
    /// There is another request for this principle
    AlreadyProcessing,

    /// The amount to withdraw is too low
    AmountTooLow(u64),

    /// The burn call to the Ledger failed
    LedgerConnectionError(i32, String),

    /// The Ledger rejected the burn operation
    LedgerError(TransferError),

    /// The bitcoin fee is too low
    FeeTooLow(u64),

    /// The bitcoin address is not valid
    MalformedAddress(String),

    /// There are too many concurrent requests, retry later
    TooManyConcurrentRequests,
}

impl From<GuardError> for RetrieveBtcErr {
    fn from(e: GuardError) -> Self {
        match e {
            GuardError::AlreadyProcessing => Self::AlreadyProcessing,
            GuardError::TooManyConcurrentRequests => Self::TooManyConcurrentRequests,
        }
    }
}

impl From<TransferError> for RetrieveBtcErr {
    fn from(e: TransferError) -> Self {
        Self::LedgerError(e)
    }
}

pub async fn retrieve_btc(args: RetrieveBtcArgs) -> Result<RetrieveBtcOk, RetrieveBtcErr> {
    let caller = ic_cdk::caller();
    init_ecdsa_public_key().await;
    let _guard = retrieve_btc_guard(caller)?;
    let (default_fee, min_amount) =
        read_state(|s| (s.retrieve_btc_min_fee, s.retrieve_btc_min_amount));
    let fee = args.fee.unwrap_or(default_fee);
    if fee < default_fee {
        return Err(RetrieveBtcErr::FeeTooLow(default_fee));
    }
    if args.amount < min_amount {
        return Err(RetrieveBtcErr::AmountTooLow(min_amount));
    }
    check_address(&args.address)?;
    if read_state(|s| s.pending_retrieve_btc_requests.len() >= MAX_CONCURRENT_PENDING_REQUESTS) {
        return Err(RetrieveBtcErr::TooManyConcurrentRequests);
    }

    let block_index = burn_ckbtcs(caller, args.amount).await?;
    let request = RetrieveBtcRequest {
        amount: args.amount,
        address: args.address,
        fee,
        block_index,
    };
    mutate_state(|s| s.pending_retrieve_btc_requests.push_back(request));
    Ok(RetrieveBtcOk { block_index })
}

/// Checks that the given address is a valid BIP-0173 address
fn check_address(address: &str) -> Result<(), RetrieveBtcErr> {
    let (found_hrp, _, _) =
        bech32::decode(address).map_err(|e| RetrieveBtcErr::MalformedAddress(e.to_string()))?;
    let expected_hrp = hrp(read_state(|s| s.btc_network));
    if found_hrp.to_lowercase() != expected_hrp {
        return Err(RetrieveBtcErr::MalformedAddress(format!(
            "Found hrp {} but expected {}",
            found_hrp, expected_hrp
        )));
    }
    Ok(())
}

async fn burn_ckbtcs(user: Principal, amount: u64) -> Result<u64, RetrieveBtcErr> {
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id: read_state(|s| s.ledger_id.get().into()),
    };
    let minter = PrincipalId(ic_cdk::id());
    let from_subaccount = compute_subaccount(PrincipalId(user), 0);
    let block_index = client
        .transfer(TransferArg {
            from_subaccount: Some(from_subaccount),
            to: Account {
                owner: minter,
                subaccount: None,
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(amount),
        })
        .await
        .map_err(|(code, msg)| RetrieveBtcErr::LedgerConnectionError(code, msg))??;
    Ok(block_index)
}

#[cfg(test)]
mod tests {
    use ic_ic00_types::BitcoinNetwork::Mainnet;

    use crate::{
        state::{replace_state, CkBtcMinterState},
        updates::retrieve_btc::check_address,
    };

    #[test]
    fn test_check_address() {
        replace_state(CkBtcMinterState {
            btc_network: Mainnet,
            ecdsa_key_name: "".to_string(),
            ecdsa_public_key: None,
            update_balance_principals: Default::default(),
            retrieve_btc_principals: Default::default(),
            retrieve_btc_min_fee: 0,
            retrieve_btc_min_amount: 0,
            pending_retrieve_btc_requests: Default::default(),
            ledger_id: ic_base_types::CanisterId::from_u64(42),
        });
        assert_eq!(
            Ok(()),
            check_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        );
        assert_eq!(
            Ok(()),
            check_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
        );

        // invalid checksum
        assert_ne!(
            Ok(()),
            check_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
        );
    }
}
