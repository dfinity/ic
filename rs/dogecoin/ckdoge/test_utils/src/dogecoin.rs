use bitcoin::hashes::Hash;
use candid::{Decode, Encode, Principal};
use ic_bitcoin_canister_mock::{PushUtxosToAddress, Utxo};
use ic_ckdoge_minter::Txid;
use ic_management_canister_types::CanisterId;
use pocket_ic::PocketIc;
use std::collections::BTreeMap;
use std::sync::Arc;

pub type Mempool = BTreeMap<Txid, bitcoin::Transaction>;

pub struct DogecoinCanister {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) id: CanisterId,
}

impl DogecoinCanister {
    fn push_utxos_to_address(&self, arg: &PushUtxosToAddress) {
        self.env
            .update_call(
                self.id,
                Principal::anonymous(),
                "push_utxos_to_address",
                Encode!(arg).unwrap(),
            )
            .expect("failed to push a UTXO");
    }

    pub fn push_utxo(&self, utxo: Utxo, address: String) {
        self.push_utxos_to_address(&PushUtxosToAddress {
            address,
            utxos: vec![utxo],
        })
    }

    pub fn push_utxos<I: IntoIterator<Item = Utxo>>(&self, utxos: I, address: String) {
        let request = PushUtxosToAddress {
            utxos: utxos.into_iter().collect(),
            address,
        };
        self.push_utxos_to_address(&request);
    }

    pub fn set_fee_percentiles(&self, fee_percentiles: [u64; 101]) {
        self.env
            .update_call(
                self.id,
                Principal::anonymous(),
                "set_fee_percentiles",
                Encode!(&fee_percentiles).unwrap(),
            )
            .expect("failed to set fee percentiles");
    }

    pub fn mempool(&self) -> Mempool {
        use bitcoin::consensus::Decodable;

        fn vec_to_txid(vec: Vec<u8>) -> Txid {
            let bytes: [u8; 32] = vec.try_into().expect("Vector length must be exactly 32");
            bytes.into()
        }

        let response = self
            .env
            .update_call(
                self.id,
                Principal::anonymous(),
                "get_mempool",
                Encode!().unwrap(),
            )
            .expect("failed to get mempool");
        let response = Decode!(&response, Vec<Vec<u8>>).unwrap();
        response
            .into_iter()
            .map(|tx_bytes| {
                let tx = bitcoin::Transaction::consensus_decode(&mut &tx_bytes[..])
                    .expect("failed to parse a dogecoin transaction");

                (vec_to_txid(tx.compute_txid().as_byte_array().to_vec()), tx)
            })
            .collect()
    }

    pub fn await_mempool<F>(&self, condition: F) -> Mempool
    where
        F: Fn(&Mempool) -> bool,
    {
        const MAX_TICKS: u8 = 10;

        let mut num_ticks = 0;
        loop {
            if num_ticks >= MAX_TICKS {
                panic!("BUG: condition not satisfied in mempool");
            }
            let mempool = self.mempool();
            if condition(&mempool) {
                return mempool;
            }
            self.env.tick();
            num_ticks += 1;
        }
    }
}
