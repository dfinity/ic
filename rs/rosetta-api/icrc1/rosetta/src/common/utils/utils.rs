use crate::{common::types::Error, AppState};
use rosetta_core::identifiers::{AccountIdentifier, NetworkIdentifier, SubAccountIdentifier};

const DEFAULT_BLOCKCHAIN: &str = "Internet Computer";

pub fn verify_network_id(
    network_identifier: &NetworkIdentifier,
    state: &AppState,
) -> Result<(), Error> {
    let expected = &NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        state.icrc1_agent.ledger_canister_id.to_string(),
    );

    if network_identifier != expected {
        return Err(Error::invalid_network_id(expected));
    }
    Ok(())
}

pub fn icrc1_account_to_rosetta_accountidentifier(
    account: &icrc_ledger_types::icrc1::account::Account,
) -> AccountIdentifier {
    AccountIdentifier {
        address: account.owner.to_string(),
        sub_account: account.subaccount.map(|s| SubAccountIdentifier {
            address: hex::encode(s),
            metadata: None,
        }),
        metadata: None,
    }
}
