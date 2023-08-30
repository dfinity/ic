use askama::Template;
use candid::Principal;
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::EthereumNetwork;
use ic_cketh_minter::eth_logs::{LogIndex, SMART_CONTRACT_ADDRESS};
use ic_cketh_minter::eth_rpc::BlockNumber;
use ic_cketh_minter::numeric::{LedgerMintIndex, TransactionNonce};
use ic_cketh_minter::state::State;

pub struct Mint {
    pub txhash: String,
    pub log_index: LogIndex,
    pub mint_block_index: LedgerMintIndex,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub ethereum_network: EthereumNetwork,
    pub ecdsa_key_name: String,
    pub minter_address: String,
    pub contract_address: String,
    pub next_transaction_nonce: TransactionNonce,
    pub last_synced_block: BlockNumber,
    pub last_finalized_block: Option<BlockNumber>,
    pub ledger_id: Principal,
    pub mints: Vec<Mint>,
}

impl DashboardTemplate {
    pub fn from_state(state: &State) -> Self {
        DashboardTemplate {
            ethereum_network: state.ethereum_network,
            ecdsa_key_name: state.ecdsa_key_name.clone(),
            minter_address: state
                .minter_address()
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            contract_address: Address::new(SMART_CONTRACT_ADDRESS).to_string(),
            ledger_id: state.ledger_id,
            next_transaction_nonce: state.next_transaction_nonce,
            last_synced_block: state.last_scraped_block_number,
            last_finalized_block: state.last_finalized_block_number,
            mints: state
                .minted_events
                .iter()
                .map(|(source, mint_block_index)| Mint {
                    txhash: source.txhash().to_string(),
                    log_index: source.log_index(),
                    mint_block_index: *mint_block_index,
                })
                .collect(),
        }
    }
}
