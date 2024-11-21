use crate::lifecycle::init::{BtcNetwork, InitArgs};
use crate::{lifecycle, ECDSAPublicKey};
use candid::Principal;
use ic_base_types::CanisterId;
use ic_btc_interface::{GetUtxosResponse, OutPoint, Utxo};
use icrc_ledger_types::icrc1::account::Account;

pub const MINTER_CANISTER_ID: Principal = Principal::from_slice(&[0, 0, 0, 0, 2, 48, 0, 7, 1, 1]);

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
        min_confirmations: Some(6),
        mode: crate::state::Mode::GeneralAvailability,
        new_kyt_principal: Some(CanisterId::from(0)),
        kyt_principal: Some(CanisterId::from(0)),
        kyt_fee: None,
    }
}

pub fn init_state(args: InitArgs) {
    lifecycle::init::init(args)
}

pub fn ecdsa_public_key() -> ECDSAPublicKey {
    const PUBLIC_KEY: [u8; 33] = [
        3, 148, 123, 81, 208, 34, 99, 144, 214, 13, 193, 18, 89, 94, 30, 185, 101, 191, 164, 124,
        208, 174, 236, 190, 3, 16, 230, 196, 9, 252, 191, 110, 127,
    ];
    const CHAIN_CODE: [u8; 32] = [
        75, 34, 9, 207, 130, 169, 36, 138, 73, 80, 39, 225, 249, 154, 160, 111, 145, 197, 192, 53,
        148, 5, 62, 21, 47, 232, 104, 195, 249, 32, 160, 189,
    ];
    ECDSAPublicKey {
        public_key: PUBLIC_KEY.to_vec(),
        chain_code: CHAIN_CODE.to_vec(),
    }
}

pub fn ledger_account() -> Account {
    Account {
        owner: Principal::from_text(
            "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
        )
        .unwrap(),
        subaccount: Some([42; 32]),
    }
}

pub fn utxo() -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: "c9535f049c9423e974ac8daddcd0353579d779cb386fd212357e199e83f4ec5f"
                .parse()
                .unwrap(),
            vout: 3,
        },
        value: 71_000,
        height: 866_994,
    }
}

pub fn ignored_utxo() -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: "6e5d7a67d7b8a94f482a6476c214aa2f42a914fd9584966a4a341ff824ca4802"
                .parse()
                .unwrap(),
            vout: 822,
        },
        value: 1_000,
        height: 836_075,
    }
}

pub fn quarantined_utxo() -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: "688f1309fe62ae66ea71959ef6d747bb63ec7c5ab3d8b1e25d8233616c3ec71a"
                .parse()
                .unwrap(),
            vout: 22,
        },
        value: 426_762,
        height: 829_081,
    }
}

pub fn get_uxos_response() -> GetUtxosResponse {
    GetUtxosResponse {
        utxos: vec![],
        tip_block_hash: hex::decode(
            "00000000000000000002716d23b6b02097a297a84da484c7a9b6427a999112d8",
        )
        .unwrap(),
        tip_height: 871160,
        next_page: None,
    }
}

pub mod mock {
    use crate::management::CallError;
    use crate::state::UtxoCheckStatus;
    use crate::updates::update_balance::{UpdateBalanceArgs, UpdateBalanceError};
    use crate::CanisterRuntime;
    use async_trait::async_trait;
    use candid::Principal;
    use ic_btc_interface::{GetUtxosRequest, GetUtxosResponse, Utxo};
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub CanisterRuntime {}

        #[async_trait]
        impl CanisterRuntime for CanisterRuntime {
            fn caller(&self) -> Principal;
            fn id(&self) -> Principal;
            fn time(&self) -> u64;
            fn global_timer_set(&self, timestamp: u64);
            async fn bitcoin_get_utxos(&self, request: &GetUtxosRequest, cycles: u64) -> Result<GetUtxosResponse, CallError>;
            async fn kyt_check_utxo( &self, utxo: &Utxo, args: &UpdateBalanceArgs) -> Result<UtxoCheckStatus, UpdateBalanceError>;
            async fn mint_ckbtc(&self, amount: u64, to: Account, memo: Memo) -> Result<u64, UpdateBalanceError>;
        }
    }
}
