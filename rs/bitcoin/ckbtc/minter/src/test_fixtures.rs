use crate::lifecycle;
use crate::lifecycle::init::{BtcNetwork, InitArgs};
use candid::Principal;
use ic_base_types::CanisterId;

pub fn init_args() -> InitArgs {
    InitArgs {
        btc_network: BtcNetwork::Mainnet,
        ecdsa_key_name: "key_1".to_string(),
        retrieve_btc_min_amount: 10_000,
        ledger_id: CanisterId::unchecked_from_principal(
            Principal::from_text("mxzaz-hqaaa-aaaar-qaada-cai")
                .unwrap()
                .into(),
        ),
        max_time_in_queue_nanos: 600_000_000_000,
        min_confirmations: Some(72),
        mode: crate::state::Mode::GeneralAvailability,
        new_kyt_principal: Some(CanisterId::from(0)),
        kyt_principal: Some(CanisterId::from(0)),
        kyt_fee: None,
    }
}

pub fn init_state(args: InitArgs) {
    lifecycle::init::init(args)
}
