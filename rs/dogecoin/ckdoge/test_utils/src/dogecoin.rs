use crate::DOGE;
use bitcoin::dogecoin;
use bitcoin::hashes::Hash;
use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_bitcoin_canister_mock::{PushUtxosToAddress, Utxo};
use ic_btc_adapter_test_utils::bitcoind::Daemon;
use ic_ckdoge_minter::Txid;
use ic_management_canister_types::CanisterId;
use pocket_ic::{PocketIc, RejectResponse};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const BLOCK_REWARD: u64 = 500_000 * DOGE;

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
                let tx = decode_dogecoin_transaction(&tx_bytes);

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

fn decode_dogecoin_transaction(tx_bytes: &[u8]) -> bitcoin::Transaction {
    use bitcoin::consensus::Decodable;

    let tx = bitcoin::Transaction::consensus_decode(&mut &tx_bytes[..])
        .expect("failed to parse a dogecoin transaction");
    assert_eq!(
        tx.version,
        bitcoin::transaction::Version::ONE,
        "Dogecoin does not support BIP-68"
    );
    for input in &tx.input {
        assert!(
            input.witness.is_empty() && !input.script_sig.is_empty(),
            "Dogecoin does not support segwit"
        );
    }
    tx
}

pub struct DogecoinDaemon {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) daemon: Arc<Daemon<dogecoin::Network>>,
}

impl DogecoinDaemon {
    pub fn setup_user_with_balance(&self) {
        // See https://github.com/dogecoin/dogecoin/blob/2c513d0172e8bc86fe9a337693b26f2fdf68a013/src/chainparams.cpp#L423
        const COINBASE_MATURITY_REGTEST: u64 = 60;

        self.mine_blocks_to(&DogecoinUsers::Miner1, COINBASE_MATURITY_REGTEST + 1);
        let _txid = self.send_transaction(
            &DogecoinUsers::Miner1,
            &DogecoinUsers::DepositUser.address(),
            BLOCK_REWARD,
        );
        self.mine_blocks_to(&DogecoinUsers::Miner2, 1);
    }

    pub fn mine_blocks(&self, num_blocks: u64) {
        self.mine_blocks_to(&DogecoinUsers::Miner1, num_blocks)
    }

    fn mine_blocks_to(&self, miner: &DogecoinUsers, num_blocks: u64) {
        const MAX_TICKS: u64 = 1000;

        let dogecoin_canister = DogecoinCanister2::new(self.env.clone());
        let miner_balance_request = GetBalanceRequest {
            address: miner.address().to_string(),
            network: NetworkInRequest::Regtest,
            min_confirmations: None,
        };
        let balance_before = dogecoin_canister
            .dogecoin_get_balance_query(&miner_balance_request)
            .unwrap_or_default();

        let mined_blocks =
            self.await_ok(|dogecoind| dogecoind.generate_to_address(num_blocks, &miner.address()));
        assert_eq!(mined_blocks.len() as u64, num_blocks);
        let expected_balance_diff = mined_blocks.len() as u128 * BLOCK_REWARD as u128;

        for _ in 0..MAX_TICKS {
            if let Ok(balance_after) =
                dogecoin_canister.dogecoin_get_balance_query(&miner_balance_request)
                && balance_after.saturating_sub(balance_before) == expected_balance_diff
            {
                return;
            }
            self.env.tick();
        }

        panic!("BUG: Failed to mine to wallet after {MAX_TICKS} ticks");
    }

    pub fn send_transaction(
        &self,
        from: &DogecoinUsers,
        to: &dogecoin::Address,
        amount: u64,
    ) -> bitcoin::Txid {
        self.await_ok(|dogecoind| dogecoind.import_private_key(from.private_key(), from.label()));
        self.await_ok(|dogecoind| {
            dogecoind.send(
                &from.address(),
                to,
                bitcoin::Amount::from_sat(amount),
                bitcoin::Amount::ZERO,
            )
        })
    }

    fn await_ok<F, T>(&self, call: F) -> T
    where
        F: Fn(
            &ic_btc_adapter_test_utils::rpc_client::RpcClient<dogecoin::Network>,
        ) -> ic_btc_adapter_test_utils::rpc_client::Result<T>,
    {
        use ic_btc_adapter_test_utils::rpc_client::RpcError;

        const TIMEOUT: Duration = Duration::from_secs(30);
        const WAITING: Duration = Duration::from_millis(500);

        let start = std::time::Instant::now();
        loop {
            match call(&self.daemon.rpc_client) {
                Ok(value) => return value,
                Err(RpcError::JsonRpc(err)) => {
                    if start.elapsed() > TIMEOUT {
                        panic!("Timed out when waiting for dogecoind; last error: {err}");
                    }
                    std::thread::sleep(WAITING);
                }
                Err(err) => panic!("Unexpected error when talking to dogecoind: {err:?}"),
            }
        }
    }
}

#[derive(CandidType, Debug, PartialEq, Eq)]
pub struct GetBalanceRequest {
    pub address: String,
    pub network: NetworkInRequest,
    pub min_confirmations: Option<u32>,
}

#[allow(dead_code)]
#[derive(CandidType, Debug, PartialEq, Eq)]
pub enum NetworkInRequest {
    /// Bitcoin Mainnet.
    Mainnet,
    /// Bitcoin Mainnet.
    #[allow(non_camel_case_types)]
    mainnet,
    /// Bitcoin Regtest.
    Regtest,
    /// Bitcoin Regtest.
    #[allow(non_camel_case_types)]
    regtest,
}

pub enum DogecoinUsers {
    /// Receive block rewards.
    Miner1,
    /// Receive block rewards.
    Miner2,
    /// User with initially zero balance.
    DepositUser,
    /// User with initially zero balance.
    WithdrawalRecipientUser,
}

impl DogecoinUsers {
    /// Output of `dogecoin-cli dumpprivkey`
    pub fn private_key(&self) -> &str {
        match self {
            Self::Miner1 => "cTsFcvMfz8LhHtBMyVBkWGr42aHELFXecY4ZPGvUkmN3Tu5Ter1e",
            Self::Miner2 => "cQsMeW4Jpxi6Mcrn6gxWzfBbGeECjRPQpY6q9SMKXCus93rNaKK6",
            Self::DepositUser => "cVJe3RYJyTgwPFr7KeKpSJ6PTiwpFqynWXp9MYmjfctmrVQKPDXb",
            DogecoinUsers::WithdrawalRecipientUser => {
                "cVo2Sckkd8DuXvLD9cANSgTjaMfviBynKBFu5UikQf99nNwME5KH"
            }
        }
    }

    pub fn address(&self) -> dogecoin::Address {
        let address = match self {
            DogecoinUsers::Miner1 => "mgcQKpmkKUv5k23sk6kx3o4o6B8DfM96mM",
            DogecoinUsers::Miner2 => "mjoDCYdX7YqtQPYpCD4Zxsa3aMDmttvqbj",
            DogecoinUsers::DepositUser => "n3zDWiJxzMzH1w8mXjruGeyzXdCKuqSk7R",
            DogecoinUsers::WithdrawalRecipientUser => "mzm3fSWxQBgBYLMxTzbhwdHheiH7iUCpVj",
        };
        address
            .parse::<dogecoin::Address<_>>()
            .unwrap()
            .require_network(dogecoin::Network::Regtest)
            .unwrap()
    }

    pub fn label(&self) -> &str {
        match self {
            DogecoinUsers::Miner1 => "miner1",
            DogecoinUsers::Miner2 => "miner2",
            DogecoinUsers::DepositUser => "deposit_user",
            DogecoinUsers::WithdrawalRecipientUser => "recipient_user",
        }
    }
}

pub struct DogecoinCanister2 {
    env: Arc<PocketIc>,
}

impl DogecoinCanister2 {
    pub const ID: Principal = Principal::from_slice(&[0_u8, 0, 0, 0, 1, 160, 0, 7, 1, 1]);

    pub fn new(env: Arc<PocketIc>) -> Self {
        Self { env }
    }

    pub fn dogecoin_get_balance_query(
        &self,
        request: &GetBalanceRequest,
    ) -> Result<u128, RejectResponse> {
        let call_result = self.env.query_call(
            Self::ID,
            Principal::anonymous(),
            "dogecoin_get_balance_query",
            Encode!(request).unwrap(),
        )?;
        Ok(Decode!(&call_result, Nat).unwrap().0.try_into().unwrap())
    }
}
