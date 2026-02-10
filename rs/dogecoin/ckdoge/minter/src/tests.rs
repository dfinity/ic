use crate::address::DogecoinAddress;
use crate::dogecoin_canister::get_dogecoin_canister_id;
use crate::{Network, ckdoge_dashboard, event::dogecoin_to_bitcoin};
use ic_base_types::CanisterId;
use ic_ckbtc_minter::lifecycle::init::InitArgs;
use ic_ckbtc_minter::{
    dashboard::DashboardBuilder,
    state::{CkBtcMinterState, Mode},
};

#[test]
fn should_have_correct_dogecoin_canister_id() {
    assert_eq!(
        get_dogecoin_canister_id(&Network::Mainnet).to_string(),
        "gordg-fyaaa-aaaan-aaadq-cai"
    );

    assert_eq!(
        get_dogecoin_canister_id(&Network::Regtest).to_string(),
        "gordg-fyaaa-aaaan-aaadq-cai"
    );
}

#[allow(deprecated)]
fn default_init_args() -> InitArgs {
    InitArgs {
        btc_network: ic_ckbtc_minter::Network::Mainnet,
        ecdsa_key_name: "".to_string(),
        deposit_btc_min_amount: None,
        retrieve_btc_min_amount: 0,
        ledger_id: CanisterId::from_u64(42),
        max_time_in_queue_nanos: 0,
        min_confirmations: None,
        mode: Mode::GeneralAvailability,
        check_fee: None,
        btc_checker_principal: None,
        kyt_principal: None,
        kyt_fee: None,
        get_utxos_cache_expiration_seconds: None,
        utxo_consolidation_threshold: None,
        max_num_inputs_in_transaction: None,
    }
}

#[test]
fn dashboard_should_have_correct_dogecoin_address() {
    use ic_ckbtc_minter::Txid;
    use ic_ckbtc_minter::state::{
        BtcTransactionRequest, FinalizedBtcRequest, FinalizedStatus, RetrieveBtcRequest,
    };
    use std::str::FromStr;

    let network = Network::Mainnet;
    let mut state = CkBtcMinterState::from(ic_ckbtc_minter::lifecycle::init::InitArgs {
        btc_network: network.into(),
        ..default_init_args()
    });
    let address_str = "DMCQ4WrtmC2oGjeFMEqasduoj4fTMAkYff";
    let address = DogecoinAddress::parse(address_str, &network).unwrap();
    let request = RetrieveBtcRequest {
        amount: 100,
        address: dogecoin_to_bitcoin(address),
        block_index: 123,
        received_at: 0,
        kyt_provider: None,
        reimbursement_account: None,
    };
    let request = BtcTransactionRequest::RetrieveBtc(request);
    let txid_str = "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599";
    let txid = Txid::from_str(txid_str).unwrap();
    let req = FinalizedBtcRequest {
        request,
        state: FinalizedStatus::Confirmed { txid },
    };
    state.finalized_requests.push_back(req);

    let dashboard = ckdoge_dashboard(network);
    let meta = dashboard.build_metadata(&state);
    assert!(meta.contains("<th>Total DOGE managed</th>"));

    let finalized = dashboard.build_finalized_requests(&state);
    assert!(finalized.contains(&format!("<code>{address_str}</code>")));
    let builder = crate::CkDogeDashboardBuilder::new(network);
    let url = builder.transaction_url(&txid);
    assert!(finalized.contains(&url));
}
