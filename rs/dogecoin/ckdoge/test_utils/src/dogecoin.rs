use candid::{Encode, Principal};
use ic_bitcoin_canister_mock::{PushUtxoToAddress, Utxo};
use ic_management_canister_types::CanisterId;
use pocket_ic::PocketIc;
use std::sync::Arc;

pub struct DogecoinCanister {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) id: CanisterId,
}

impl DogecoinCanister {
    fn push_utxo_to_address(&self, arg: &PushUtxoToAddress) {
        self.env
            .update_call(
                self.id,
                Principal::anonymous(),
                "push_utxo_to_address",
                Encode!(arg).unwrap(),
            )
            .expect("failed to push a UTXO");
    }

    pub fn simulate_transaction(&self, utxo: Utxo, address: String) {
        self.push_utxo_to_address(&PushUtxoToAddress { address, utxo })
    }
}
