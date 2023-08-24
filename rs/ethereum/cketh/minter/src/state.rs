use crate::endpoints::{EthereumNetwork, InitArg};
use crate::eth_logs::{EventSource, ReceivedEthEvent};
use crate::eth_rpc::BlockNumber;
use crate::logs::DEBUG;
use crate::numeric::{LedgerBurnIndex, LedgerMintIndex, TransactionNonce};
use crate::transactions::PendingEthTransactions;
use crate::tx::Eip1559TransactionRequest;
use candid::Principal;
use ic_canister_log::log;
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;
use ic_crypto_ecdsa_secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

thread_local! {
    pub static STATE: RefCell<Option<State>> = RefCell::default();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub ethereum_network: EthereumNetwork,
    pub ecdsa_key_name: String,
    pub ledger_id: Principal,
    pub ecdsa_public_key: Option<EcdsaPublicKeyResponse>,
    pub last_seen_block_number: BlockNumber,
    pub events_to_mint: BTreeSet<ReceivedEthEvent>,
    pub minted_events: BTreeMap<EventSource, LedgerMintIndex>,
    pub invalid_events: BTreeSet<EventSource>,
    pub pending_retrieve_eth_requests: PendingEthTransactions,
    pub next_transaction_nonce: TransactionNonce,

    /// Per-principal lock for pending_retrieve_eth_requests
    #[serde(skip)]
    pub retrieve_eth_principals: BTreeSet<Principal>,

    /// A lock preventing concurrent execution of the task processing retrieve_eth events.
    #[serde(skip)]
    pub retrieve_eth_guarded: bool,

    /// A lock preventing concurrent execution of the task minting ckETH.
    #[serde(skip)]
    pub cketh_mint_guarded: bool,
}

impl Default for State {
    fn default() -> Self {
        let next_transaction_nonce = TransactionNonce::ZERO;
        let ethereum_network = EthereumNetwork::default();
        Self {
            ethereum_network,
            ecdsa_key_name: "test_key_1".to_string(),
            ledger_id: Principal::anonymous(),
            ecdsa_public_key: None,
            // Note that the default block to start from for logs scrapping
            // depends on the chain we are using:
            // Ethereum and Sepolia have for example different block heights at a given time.
            // https://sepolia.etherscan.io/block/3938798
            last_seen_block_number: BlockNumber::new(3_956_206),
            events_to_mint: Default::default(),
            minted_events: Default::default(),
            invalid_events: Default::default(),
            next_transaction_nonce,
            retrieve_eth_principals: BTreeSet::new(),
            pending_retrieve_eth_requests: PendingEthTransactions::new(next_transaction_nonce),
            retrieve_eth_guarded: false,
            cketh_mint_guarded: false,
        }
    }
}

impl From<InitArg> for State {
    fn from(
        InitArg {
            ethereum_network,
            ecdsa_key_name,
            ledger_id,
            next_transaction_nonce,
        }: InitArg,
    ) -> Self {
        let initial_nonce = TransactionNonce::try_from(next_transaction_nonce)
            .expect("BUG: initial nonce must be less than U256::MAX");
        Self {
            ethereum_network,
            ecdsa_key_name,
            next_transaction_nonce: initial_nonce,
            pending_retrieve_eth_requests: PendingEthTransactions::new(initial_nonce),
            ledger_id,
            ..Self::default()
        }
    }
}

impl State {
    pub fn get_and_increment_nonce(&mut self) -> TransactionNonce {
        let current_nonce = self.next_transaction_nonce;
        self.next_transaction_nonce = self
            .next_transaction_nonce
            .checked_increment()
            .expect("transaction nonce overflow only possible after U256::MAX transactions");
        current_nonce
    }

    pub fn record_retrieve_eth_request(
        &mut self,
        leder_burn_index: LedgerBurnIndex,
        transaction: Eip1559TransactionRequest,
    ) {
        debug_assert_eq!(
            self.pending_retrieve_eth_requests
                .insert(leder_burn_index, transaction),
            Ok(())
        );
    }

    pub fn record_event_to_mint(&mut self, event: ReceivedEthEvent) {
        debug_assert!(
            self.events_to_mint
                .iter()
                .all(|e| e == &event || e.source() != event.source()),
            "there must be no two different events with the same source"
        );

        debug_assert!(!self.minted_events.contains_key(&event.source()));
        debug_assert!(!self.invalid_events.contains(&event.source()));

        self.events_to_mint.insert(event);
    }

    pub fn record_invalid_deposit(&mut self, source: EventSource) -> bool {
        debug_assert!(
            self.events_to_mint.iter().all(|e| e.source() != source),
            "attempted to mark an accepted event as invalid"
        );
        assert!(
            !self.minted_events.contains_key(&source),
            "attempted to mark a minted event {source:?} as invalid"
        );

        self.invalid_events.insert(source)
    }

    pub fn record_successful_mint(
        &mut self,
        event: &ReceivedEthEvent,
        mint_block_index: LedgerMintIndex,
    ) {
        debug_assert!(
            !self.invalid_events.contains(&event.source()),
            "attempted to mint an event previously marked as invalid {event:?}"
        );

        assert!(
            self.events_to_mint.remove(event),
            "attempted to mint ckETH for an unknown event {event:?}"
        );
        assert_eq!(
            self.minted_events.insert(event.source(), mint_block_index),
            None,
            "attempted to mint ckETH twice for the same event {event:?}"
        );
    }

    pub const fn ethereum_network(&self) -> EthereumNetwork {
        self.ethereum_network
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
