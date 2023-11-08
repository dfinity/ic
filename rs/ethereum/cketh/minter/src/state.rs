use crate::address::Address;
use crate::eth_logs::{EventSource, ReceivedEthEvent};
use crate::eth_rpc::BlockTag;
use crate::lifecycle::upgrade::UpgradeArg;
use crate::lifecycle::EvmNetwork;
use crate::logs::DEBUG;
use crate::numeric::{BlockNumber, LedgerMintIndex, TransactionNonce, Wei};
use crate::transactions::EthTransactions;
use candid::Principal;
use ic_canister_log::log;
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;
use ic_crypto_ecdsa_secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{btree_map, BTreeMap, BTreeSet, HashSet};
use strum_macros::EnumIter;

pub mod audit;
pub mod event;

#[cfg(test)]
mod tests;

thread_local! {
    // pub static STATE: RefCell<Option<State>> = RefCell::default();
    pub static STATE: RefCell<Option<State>> = RefCell::new(Some(State {
        ethereum_network: EvmNetwork::Ethereum,
        ecdsa_key_name: "".to_string(),
        ledger_id: Principal::anonymous(),
        ethereum_contract_address: None,
        ecdsa_public_key: None,
        minimum_withdrawal_amount: 0_u128.into(),
        ethereum_block_height: BlockTag::Latest,
        last_scraped_block_number: 0_u128.into(),
        last_observed_block_number: None,
        events_to_mint: BTreeMap::new(),
        minted_events: BTreeMap::new(),
        invalid_events: BTreeMap::new(),
        eth_transactions: EthTransactions::new(0_u128.into()),
        retrieve_eth_principals: BTreeSet::new(),
        active_tasks: HashSet::new(),
        http_request_counter: 0,
    }));
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct MintedEvent {
    pub deposit_event: ReceivedEthEvent,
    pub mint_block_index: LedgerMintIndex,
}

impl MintedEvent {
    pub fn source(&self) -> EventSource {
        self.deposit_event.source()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct State {
    pub ethereum_network: EvmNetwork,
    pub ecdsa_key_name: String,
    pub ledger_id: Principal,
    pub ethereum_contract_address: Option<Address>,
    pub ecdsa_public_key: Option<EcdsaPublicKeyResponse>,
    pub minimum_withdrawal_amount: Wei,
    pub ethereum_block_height: BlockTag,
    pub last_scraped_block_number: BlockNumber,
    pub last_observed_block_number: Option<BlockNumber>,
    pub events_to_mint: BTreeMap<EventSource, ReceivedEthEvent>,
    pub minted_events: BTreeMap<EventSource, MintedEvent>,
    pub invalid_events: BTreeMap<EventSource, String>,
    pub eth_transactions: EthTransactions,

    /// Per-principal lock for pending_retrieve_eth_requests
    #[serde(skip)]
    pub retrieve_eth_principals: BTreeSet<Principal>,

    /// Locks preventing concurrent execution timer tasks
    #[serde(skip)]
    pub active_tasks: HashSet<TaskType>,

    /// Number of HTTP outcalls since the last upgrade.
    /// Used to correlate request and response in logs.
    #[serde(skip)]
    pub http_request_counter: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum InvalidStateError {
    InvalidTransactionNonce(String),
    InvalidEcdsaKeyName(String),
    InvalidLedgerId(String),
    InvalidEthereumContractAddress(String),
    InvalidMinimumWithdrawalAmount(String),
}

impl State {
    pub fn validate_config(&self) -> Result<(), InvalidStateError> {
        if self.ecdsa_key_name.trim().is_empty() {
            return Err(InvalidStateError::InvalidEcdsaKeyName(
                "ecdsa_key_name cannot be blank".to_string(),
            ));
        }
        if self.ledger_id == Principal::anonymous() {
            return Err(InvalidStateError::InvalidLedgerId(
                "ledger_id cannot be the anonymous principal".to_string(),
            ));
        }
        if self
            .ethereum_contract_address
            .iter()
            .any(|address| address == &Address::ZERO)
        {
            return Err(InvalidStateError::InvalidEthereumContractAddress(
                "ethereum_contract_address cannot be the zero address".to_string(),
            ));
        }
        if self.minimum_withdrawal_amount == Wei::ZERO {
            return Err(InvalidStateError::InvalidMinimumWithdrawalAmount(
                "minimum_withdrawal_amount must be positive".to_string(),
            ));
        }
        Ok(())
    }

    pub fn minter_address(&self) -> Option<Address> {
        let pubkey = PublicKey::deserialize_sec1(&self.ecdsa_public_key.as_ref()?.public_key)
            .unwrap_or_else(|e| {
                ic_cdk::trap(&format!("failed to decode minter's public key: {:?}", e))
            });
        Some(Address::from_pubkey(&pubkey))
    }

    fn record_event_to_mint(&mut self, event: ReceivedEthEvent) {
        let event_source = event.source();
        assert!(
            !self.events_to_mint.contains_key(&event_source),
            "there must be no two different events with the same source"
        );
        assert!(!self.minted_events.contains_key(&event_source));
        assert!(!self.invalid_events.contains_key(&event_source));

        self.events_to_mint.insert(event_source, event);
    }

    fn record_invalid_deposit(&mut self, source: EventSource, error: String) -> bool {
        assert!(
            !self.events_to_mint.contains_key(&source),
            "attempted to mark an accepted event as invalid"
        );
        assert!(
            !self.minted_events.contains_key(&source),
            "attempted to mark a minted event {source:?} as invalid"
        );

        match self.invalid_events.entry(source) {
            btree_map::Entry::Occupied(_) => false,
            btree_map::Entry::Vacant(entry) => {
                entry.insert(error);
                true
            }
        }
    }

    fn record_successful_mint(&mut self, source: EventSource, mint_block_index: LedgerMintIndex) {
        assert!(
            !self.invalid_events.contains_key(&source),
            "attempted to mint an event previously marked as invalid {source:?}"
        );
        let deposit_event = match self.events_to_mint.remove(&source) {
            Some(event) => event,
            None => panic!("attempted to mint ckETH for an unknown event {source:?}"),
        };

        assert_eq!(
            self.minted_events.insert(
                source,
                MintedEvent {
                    deposit_event,
                    mint_block_index
                }
            ),
            None,
            "attempted to mint ckETH twice for the same event {source:?}"
        );
    }

    pub fn next_request_id(&mut self) -> u64 {
        let current_request_id = self.http_request_counter;
        // overflow is not an issue here because we only use `next_request_id` to correlate
        // requests and responses in logs.
        self.http_request_counter = self.http_request_counter.wrapping_add(1);
        current_request_id
    }

    pub const fn ethereum_network(&self) -> EvmNetwork {
        self.ethereum_network
    }

    pub const fn ethereum_block_height(&self) -> BlockTag {
        self.ethereum_block_height
    }

    fn upgrade(&mut self, upgrade_args: UpgradeArg) -> Result<(), InvalidStateError> {
        use std::str::FromStr;

        let UpgradeArg {
            next_transaction_nonce,
            minimum_withdrawal_amount,
            ethereum_contract_address,
            ethereum_block_height,
        } = upgrade_args;
        if let Some(nonce) = next_transaction_nonce {
            let nonce = TransactionNonce::try_from(nonce)
                .map_err(|e| InvalidStateError::InvalidTransactionNonce(format!("ERROR: {}", e)))?;
            self.eth_transactions.update_next_transaction_nonce(nonce);
        }
        if let Some(amount) = minimum_withdrawal_amount {
            let minimum_withdrawal_amount = Wei::try_from(amount).map_err(|e| {
                InvalidStateError::InvalidMinimumWithdrawalAmount(format!("ERROR: {}", e))
            })?;
            self.minimum_withdrawal_amount = minimum_withdrawal_amount;
        }
        if let Some(address) = ethereum_contract_address {
            let ethereum_contract_address = Address::from_str(&address).map_err(|e| {
                InvalidStateError::InvalidEthereumContractAddress(format!("ERROR: {}", e))
            })?;
            self.ethereum_contract_address = Some(ethereum_contract_address);
        }
        if let Some(block_height) = ethereum_block_height {
            self.ethereum_block_height = block_height.into();
        }
        self.validate_config()
    }
}

pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(s.borrow().as_ref().expect("BUG: state is not initialized")))
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| {
        f(s.borrow_mut()
            .as_mut()
            .expect("BUG: state is not initialized"))
    })
}

pub async fn lazy_call_ecdsa_public_key() -> PublicKey {
    use ic_cdk::api::management_canister::ecdsa::{
        ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    };

    fn to_public_key(response: &EcdsaPublicKeyResponse) -> PublicKey {
        PublicKey::deserialize_sec1(&response.public_key).unwrap_or_else(|e| {
            ic_cdk::trap(&format!("failed to decode minter's public key: {:?}", e))
        })
    }

    if let Some(ecdsa_pk_response) = read_state(|s| s.ecdsa_public_key.clone()) {
        return to_public_key(&ecdsa_pk_response);
    }
    let key_name = read_state(|s| s.ecdsa_key_name.clone());
    log!(DEBUG, "Fetching the ECDSA public key {key_name}");
    let (response,) = ecdsa_public_key(EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: crate::MAIN_DERIVATION_PATH
            .into_iter()
            .map(|x| x.to_vec())
            .collect(),
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    })
    .await
    .unwrap_or_else(|(error_code, message)| {
        ic_cdk::trap(&format!(
            "failed to get minter's public key: {} (error code = {:?})",
            message, error_code,
        ))
    });
    mutate_state(|s| s.ecdsa_public_key = Some(response.clone()));
    to_public_key(&response)
}

pub async fn minter_address() -> Address {
    Address::from_pubkey(&lazy_call_ecdsa_public_key().await)
}

#[derive(Serialize, Deserialize, Debug, Hash, Copy, Clone, PartialEq, Eq, EnumIter)]
pub enum TaskType {
    MintCkEth,
    RetrieveEth,
    ScrapEthLogs,
}
