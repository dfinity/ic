use crate::endpoints::InitArg;
use crate::eth_rpc::BlockNumber;
use crate::eth_rpc::Hash;
use std::cell::RefCell;
use std::collections::BTreeSet;

thread_local! {
    pub static STATE: RefCell<Option<State>> = RefCell::default();
}

pub struct State {
    pub ecdsa_key_name: String,
    pub last_seen_block_number: BlockNumber,
    pub minted_transactions: BTreeSet<Hash>,
    pub invalid_transactions: BTreeSet<Hash>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            ecdsa_key_name: "test_key_1".to_string(),
            // Note that the default block to start from for logs scrapping
            // depends on the chain we are using:
            // Ethereum and Sepolia have for example different block heights at a given time.
            // https://sepolia.etherscan.io/block/3938798
            last_seen_block_number: BlockNumber::new(3_956_206),
            minted_transactions: BTreeSet::new(),
            invalid_transactions: BTreeSet::new(),
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
