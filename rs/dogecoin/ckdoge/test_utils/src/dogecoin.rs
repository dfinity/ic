use crate::DOGE;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, dogecoin};
use candid::{Decode, Encode, Principal};
use ic_btc_adapter_test_utils::bitcoind::Daemon;
use pocket_ic::{PocketIc, RejectResponse};
use std::sync::Arc;
use std::time::Duration;

const BLOCK_REWARD: u64 = 500_000 * DOGE;

pub struct DogecoinDaemon {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) daemon: Arc<Daemon<dogecoin::Network>>,
}

impl DogecoinDaemon {
    /// Set up a user having a single UTXO with value [`BLOCK_REWARD`] doge.
    ///
    /// Internally, what it does is the following
    /// * Mines 1 + 60 blocks to the miner, where the last 60 blocks are required to be able to spend the coins from the coinbase transaction in the first block
    /// * Transfer 1 block reward from the miner to the user.
    /// * Mine a last block to include this last transaction.
    pub fn setup_user_with_balance(&self) {
        // See https://github.com/dogecoin/dogecoin/blob/2c513d0172e8bc86fe9a337693b26f2fdf68a013/src/chainparams.cpp#L423
        const COINBASE_MATURITY_REGTEST: u64 = 60;

        self.mine_blocks_to(&DogecoinUsers::Miner, COINBASE_MATURITY_REGTEST + 1);
        let _txid = self.send_transaction(
            &DogecoinUsers::Miner,
            &DogecoinUsers::DepositUser.address(),
            vec![BLOCK_REWARD],
        );
        self.mine_blocks_to(&DogecoinUsers::Miner, 1);
    }

    pub fn mine_blocks(&self, num_blocks: u64) {
        self.mine_blocks_to(&DogecoinUsers::Miner, num_blocks)
    }

    pub fn mine_blocks_to(&self, miner: &DogecoinUsers, num_blocks: u64) {
        let _sync_guard = DogecoinSyncGuard::new(self);

        let mined_blocks =
            self.await_ok(|dogecoind| dogecoind.generate_to_address(num_blocks, &miner.address()));
        assert_eq!(mined_blocks.len() as u64, num_blocks);
    }

    /// Send a single transaction with potentially multiple outputs: one for each amount to the given recipient.
    pub fn send_transaction<I: IntoIterator<Item = u64>>(
        &self,
        from: &DogecoinUsers,
        to: &dogecoin::Address,
        amounts: I,
    ) -> bitcoin::Txid {
        self.await_ok(|dogecoind| dogecoind.import_private_key(from.private_key(), from.label()));
        let from_address = from.address();
        let fee = bitcoin::Amount::ZERO;
        let unspent =
            self.await_ok(|dogecoind| dogecoind.list_unspent(Some(0), Some(&[&from_address])));
        let total_unspent: Amount = unspent.iter().map(|x| x.amount).sum();
        let mut outputs: Vec<(&dogecoin::Address, Amount)> = amounts
            .into_iter()
            .map(|amount| (to, Amount::from_sat(amount)))
            .collect();
        let total_amount = outputs
            .iter()
            .map(|(_address, amount)| amount)
            .copied()
            .sum();
        assert!(
            total_unspent >= total_amount,
            "BUG: trying to spend {total_amount} when only {total_unspent} is available"
        );

        if total_unspent > total_amount + fee {
            outputs.push((&from_address, total_unspent - total_amount - fee));
        }
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: unspent
                .into_iter()
                .map(|input| bitcoin::transaction::TxIn {
                    previous_output: bitcoin::transaction::OutPoint {
                        txid: input.txid,
                        vout: input.vout,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::default(),
                })
                .collect(),
            output: outputs
                .into_iter()
                .map(|(address, amount)| bitcoin::TxOut {
                    value: amount,
                    script_pubkey: address.script_pubkey(),
                })
                .collect(),
        };
        let signed_tx = self.await_ok(|dogecoind| dogecoind.sign_raw_transaction(&tx, None));
        self.await_ok(|dogecoind| dogecoind.send_raw_transaction::<&[u8]>(signed_tx.hex.as_ref()))
    }

    pub fn get_raw_transaction_from_mempool(
        &self,
        txid: ic_ckdoge_minter::Txid,
    ) -> bitcoin::Transaction {
        self.await_ok(|daemon| {
            daemon.get_raw_transaction_from_mempool(&bitcoin::Txid::from_byte_array(txid.into()))
        })
    }

    pub fn deprioritize_transaction_from_mempool(&self, txid: &bitcoin::Txid) {
        self.await_ok(|daemon| {
            daemon.set_transaction_priority_in_mempool(txid, i32::MIN, i32::MIN)
        });
    }

    pub fn mempool(&self) -> Vec<bitcoin::Txid> {
        self.await_ok(|dogecoind| dogecoind.get_raw_mempool())
    }

    pub fn await_ok<F, T>(&self, call: F) -> T
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
                    self.env.tick();
                    std::thread::sleep(WAITING);
                }
                Err(err) => panic!("Unexpected error when talking to dogecoind: {err:?}"),
            }
        }
    }
}

pub enum DogecoinUsers {
    /// Receive block rewards.
    Miner,
    /// User with initially zero balance.
    DepositUser,
    /// User with initially zero balance.
    WithdrawalRecipientUser,
}

impl DogecoinUsers {
    /// Output of `dogecoin-cli dumpprivkey`
    pub fn private_key(&self) -> &str {
        match self {
            Self::Miner => "cTsFcvMfz8LhHtBMyVBkWGr42aHELFXecY4ZPGvUkmN3Tu5Ter1e",
            Self::DepositUser => "cVJe3RYJyTgwPFr7KeKpSJ6PTiwpFqynWXp9MYmjfctmrVQKPDXb",
            DogecoinUsers::WithdrawalRecipientUser => {
                "cVo2Sckkd8DuXvLD9cANSgTjaMfviBynKBFu5UikQf99nNwME5KH"
            }
        }
    }

    pub fn address(&self) -> dogecoin::Address {
        let address = match self {
            DogecoinUsers::Miner => "mgcQKpmkKUv5k23sk6kx3o4o6B8DfM96mM",
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
            DogecoinUsers::Miner => "miner",
            DogecoinUsers::DepositUser => "deposit_user",
            DogecoinUsers::WithdrawalRecipientUser => "recipient_user",
        }
    }
}

/// Guard to ensure that the Dogecoin canister is caught up with the Dogecoin daemon.
pub struct DogecoinSyncGuard<'a> {
    daemon: &'a DogecoinDaemon,
}

impl<'a> DogecoinSyncGuard<'a> {
    pub fn new(daemon: &'a DogecoinDaemon) -> Self {
        Self { daemon }
    }
}

impl Drop for DogecoinSyncGuard<'_> {
    fn drop(&mut self) {
        const MAX_TICKS: u64 = 1000;

        let dogecoin_canister = DogecoinCanister::new(self.daemon.env.clone());
        let dogecoin_block_height = self
            .daemon
            .await_ok(|dogecoind| dogecoind.get_blockchain_info())
            .blocks;

        for _ in 0..MAX_TICKS {
            match dogecoin_canister.get_block_height() {
                Ok(dogecoin_canister_block_height)
                    if dogecoin_canister_block_height >= dogecoin_block_height =>
                {
                    return;
                }
                result => {
                    println!("Dogecoin canister not ready {result:?}");
                    self.daemon.env.tick();
                }
            }
        }

        panic!(
            "BUG: dogecoin canister did not reach block height {dogecoin_block_height} after {MAX_TICKS} ticks"
        );
    }
}

pub struct DogecoinCanister {
    env: Arc<PocketIc>,
}

impl DogecoinCanister {
    pub const ID: Principal = Principal::from_slice(&[0_u8, 0, 0, 0, 1, 160, 0, 7, 1, 1]);

    pub fn new(env: Arc<PocketIc>) -> Self {
        Self { env }
    }

    pub fn get_block_height(&self) -> Result<u64, RejectResponse> {
        let request = ic_doge_interface::GetUtxosRequest {
            address: DogecoinUsers::Miner.address().to_string(),
            network: ic_doge_interface::NetworkInRequest::Regtest,
            filter: None,
        };
        self.env
            .query_call(
                DogecoinCanister::ID,
                Principal::anonymous(),
                "dogecoin_get_utxos_query",
                Encode!(&request).unwrap(),
            )
            .map(|response| {
                Decode!(&response, ic_doge_interface::GetUtxosResponse)
                    .unwrap()
                    .tip_height as u64
            })
    }
}
