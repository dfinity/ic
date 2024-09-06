use candid::candid_method;
use ic_btc_interface::{
    Address, GetCurrentFeePercentilesRequest, GetUtxosRequest, GetUtxosResponse,
    MillisatoshiPerByte, Network, Utxo, UtxosFilterInRequest,
};
use ic_cdk::api::management_canister::bitcoin::{BitcoinNetwork, SendTransactionRequest};
use ic_cdk_macros::{init, update};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

// We use 12 as the default tip height to mint all
// the utxos with height 1 in the minter.
const DEFAULT_TIP_HEIGHT: u32 = 12;

fn main() {}

#[derive(Clone, Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
pub struct State {
    pub fee_percentiles: Vec<u64>,
    // The network used in the bitcoin canister.
    pub network: Network,
    // Is the bitcoin canister available.
    pub is_available: bool,
    pub address_to_utxos: BTreeMap<Address, BTreeSet<Utxo>>,
    pub utxo_to_address: BTreeMap<Utxo, Address>,
    // Pending transactions.
    pub mempool: BTreeSet<ByteBuf>,
    pub tip_height: u32,
}

impl Default for State {
    fn default() -> Self {
        State {
            fee_percentiles: [0; 100].into(),
            network: Network::Mainnet,
            is_available: true,
            address_to_utxos: BTreeMap::new(),
            utxo_to_address: BTreeMap::new(),
            mempool: BTreeSet::new(),
            tip_height: DEFAULT_TIP_HEIGHT,
        }
    }
}

pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| f(&mut s.borrow_mut()))
}

pub fn read_state<F, R>(f: F) -> R
where
    F: FnOnce(&State) -> R,
{
    STATE.with(|s| f(&s.borrow()))
}

thread_local! {
    static STATE: RefCell<State> = RefCell::default();
}

#[init]
fn init(network: Network) {
    STATE.with(|s| {
        let state = State {
            network,
            fee_percentiles: [0; 100].into(),
            is_available: true,
            utxo_to_address: BTreeMap::new(),
            address_to_utxos: BTreeMap::new(),
            mempool: BTreeSet::new(),
            tip_height: DEFAULT_TIP_HEIGHT,
        };
        *s.borrow_mut() = state;
    });
}

#[candid_method(update)]
#[update]
fn set_tip_height(tip_height: u32) {
    mutate_state(|s| s.tip_height = tip_height);
}

#[candid_method(update)]
#[update]
fn bitcoin_get_utxos(utxos_request: GetUtxosRequest) -> GetUtxosResponse {
    read_state(|s| {
        assert_eq!(utxos_request.network, s.network.into());

        let mut utxos = s
            .address_to_utxos
            .get(&utxos_request.address)
            .cloned()
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect::<Vec<Utxo>>();

        if let Some(UtxosFilterInRequest::MinConfirmations(min_confirmations)) =
            utxos_request.filter
        {
            utxos.retain(|u| s.tip_height + 1 >= u.height + min_confirmations);
        }

        GetUtxosResponse {
            utxos,
            tip_block_hash: vec![],
            tip_height: s.tip_height,
            // TODO Handle pagination.
            next_page: None,
        }
    })
}

#[candid_method(update)]
#[update]
fn push_utxo_to_address(req: ic_bitcoin_canister_mock::PushUtxoToAddress) {
    mutate_state(|s| {
        s.utxo_to_address
            .insert(req.utxo.clone(), req.address.clone());
        s.address_to_utxos
            .entry(req.address)
            .or_default()
            .insert(req.utxo);
    });
}

#[candid_method(update)]
#[update]
fn remove_utxo(utxo: Utxo) {
    let address = read_state(|s| s.utxo_to_address.get(&utxo).cloned().unwrap());
    mutate_state(|s| {
        s.utxo_to_address.remove(&utxo);
        s.address_to_utxos
            .get_mut(&address)
            .expect("utxo not found at address")
            .remove(&utxo);
    });
}

#[candid_method(update)]
#[update]
fn bitcoin_get_current_fee_percentiles(
    _: GetCurrentFeePercentilesRequest,
) -> Vec<MillisatoshiPerByte> {
    read_state(|s| s.fee_percentiles.clone())
}

#[candid_method(update)]
#[update]
fn set_fee_percentiles(fee_percentiles: Vec<MillisatoshiPerByte>) {
    mutate_state(|s| s.fee_percentiles = fee_percentiles);
}

#[candid_method(update)]
#[update]
fn bitcoin_send_transaction(transaction: SendTransactionRequest) {
    mutate_state(|s| {
        let cdk_network = match transaction.network {
            BitcoinNetwork::Mainnet => Network::Mainnet,
            BitcoinNetwork::Testnet => Network::Testnet,
            BitcoinNetwork::Regtest => Network::Regtest,
        };
        assert_eq!(cdk_network, s.network);
        if s.is_available {
            s.mempool.insert(ByteBuf::from(transaction.transaction));
        }
    })
}

#[candid_method(update)]
#[update]
fn change_availability(is_available: bool) {
    mutate_state(|s| s.is_available = is_available);
}

#[candid_method(update)]
#[update]
fn get_mempool() -> Vec<ByteBuf> {
    read_state(|s| s.mempool.iter().cloned().collect::<Vec<ByteBuf>>())
}

#[candid_method(update)]
#[update]
fn reset_mempool() {
    mutate_state(|s| s.mempool = BTreeSet::new());
}

#[test]
fn check_candid_interface_compatibility() {
    fn source_to_str(source: &candid_parser::utils::CandidSource) -> String {
        match source {
            candid_parser::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid_parser::utils::CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_equal(
        new_name: &str,
        new: candid_parser::utils::CandidSource,
        old_name: &str,
        old: candid_parser::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid_parser::utils::service_equal(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{} is not compatible with {}!\n\n\
            {}:\n\
            {}\n\n\
            {}:\n\
            {}\n",
                    new_name, old_name, new_name, new_str, old_name, old_str
                );
                panic!("{:?}", e);
            }
        }
    }

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("bitcoin_mock.did");

    check_service_equal(
        "actual ledger candid interface",
        candid_parser::utils::CandidSource::Text(&new_interface),
        "declared candid interface in bitcoin_mock.did file",
        candid_parser::utils::CandidSource::File(old_interface.as_path()),
    );
}
