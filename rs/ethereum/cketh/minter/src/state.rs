use crate::endpoints::InitArg;
use crate::eth_rpc::BlockNumber;
use crate::eth_rpc::Hash;
use crate::numeric::TransactionNonce;
use crate::transactions::PendingEthTransactions;
use candid::Principal;
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;
use ic_crypto_ecdsa_secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeSet;

thread_local! {
    pub static STATE: RefCell<Option<State>> = RefCell::default();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub ecdsa_key_name: String,
    pub ecdsa_public_key: Option<EcdsaPublicKeyResponse>,
    pub last_seen_block_number: BlockNumber,
    pub minted_transactions: BTreeSet<Hash>,
    pub invalid_transactions: BTreeSet<Hash>,
    pub num_issued_transactions: TransactionNonce,

    /// Per-principal lock for pending_retrieve_eth_requests
    pub retrieve_eth_principals: BTreeSet<Principal>,
    pub pending_retrieve_eth_requests: PendingEthTransactions,
    /// Process one timer event at a time for withdrawal flow.
    pub is_retrieve_eth_timer_running: bool,
}

impl Default for State {
    fn default() -> Self {
        let initial_nonce = TransactionNonce::from(3);
        Self {
            ecdsa_key_name: "test_key_1".to_string(),
            ecdsa_public_key: None,
            // Note that the default block to start from for logs scrapping
            // depends on the chain we are using:
            // Ethereum and Sepolia have for example different block heights at a given time.
            // https://sepolia.etherscan.io/block/3938798
            last_seen_block_number: BlockNumber::new(3_956_206),
            minted_transactions: BTreeSet::new(),
            invalid_transactions: BTreeSet::new(),
            num_issued_transactions: initial_nonce,
            retrieve_eth_principals: BTreeSet::new(),
            pending_retrieve_eth_requests: PendingEthTransactions::new(
                initial_nonce
                    .checked_increment()
                    .expect("transaction nonce overflow"),
            ),
            is_retrieve_eth_timer_running: false,
        }
    }
}

impl From<InitArg> for State {
    fn from(InitArg { ecdsa_key_name }: InitArg) -> Self {
        Self {
            ecdsa_key_name,
            ..Self::default()
        }
    }
}

impl State {
    pub fn increment_and_get_nonce(&mut self) -> TransactionNonce {
        let incremented_nonce = self
            .num_issued_transactions
            .checked_increment()
            .expect("transaction nonce overflow");
        self.num_issued_transactions = incremented_nonce;
        incremented_nonce
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
    ic_cdk::println!("Fetching the ECDSA public key {}", &key_name);
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
