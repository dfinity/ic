mod basic_tests;
mod rosetta_cli_tests;
mod store_tests;

use ic_rosetta_api::errors::ApiError;
use ic_rosetta_api::models::{
    AccountBalanceRequest, EnvelopePair, PartialBlockIdentifier, SignedTransaction,
};
use ic_rosetta_api::request_types::{
    Request, RequestResult, RequestType, Status, TransactionResults,
};
use ledger_canister::{
    self, AccountIdentifier, Block, BlockHeight, Operation, SendArgs, Tokens, TransferFee,
    DEFAULT_TRANSFER_FEE,
};
use tokio::sync::RwLock;

use async_trait::async_trait;
use dfn_core::CanisterId;
use ic_rosetta_api::balance_book::BalanceBook;

use ic_rosetta_api::convert::{from_arg, to_model_account_identifier};
use ic_rosetta_api::ledger_client::blocks::Blocks;
use ic_rosetta_api::ledger_client::LedgerAccess;
use ic_rosetta_api::request_handler::RosettaRequestHandler;
use ic_rosetta_api::rosetta_server::RosettaApiServer;
use ic_rosetta_api::{store::HashedBlock, DEFAULT_TOKEN_SYMBOL};
use ic_types::{
    messages::{HttpCallContent, HttpCanisterUpdate},
    PrincipalId,
};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::ops::Deref;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ic_nns_governance::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use ic_rosetta_test_utils::{acc_id, sample_data::Scribe};

fn init_test_logger() {
    // Unfortunately cargo test doesn't capture stdout properly
    // so we set the level to warn (so we don't spam).
    // I tried to use env logger here, which is supposed to work,
    // and sure, cargo test captures it's output on MacOS, but it
    // doesn't on linux.
    log4rs::init_file("log_config_tests.yml", Default::default()).ok();
}

fn create_tmp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("test_tmp_")
        .tempdir_in(".")
        .unwrap()
}

pub struct TestLedger {
    pub blockchain: RwLock<Blocks>,
    pub canister_id: CanisterId,
    pub governance_canister_id: CanisterId,
    pub submit_queue: RwLock<Vec<HashedBlock>>,
    pub transfer_fee: Tokens,
}

impl TestLedger {
    pub fn new() -> Self {
        Self {
            blockchain: RwLock::new(Blocks::new_in_memory()),
            canister_id: CanisterId::new(
                PrincipalId::from_str("5v3p4-iyaaa-aaaaa-qaaaa-cai").unwrap(),
            )
            .unwrap(),
            governance_canister_id: ic_nns_constants::GOVERNANCE_CANISTER_ID,
            submit_queue: RwLock::new(Vec::new()),
            transfer_fee: DEFAULT_TRANSFER_FEE,
        }
    }

    pub fn from_blockchain(blocks: Blocks) -> Self {
        Self {
            blockchain: RwLock::new(blocks),
            ..Default::default()
        }
    }

    async fn last_submitted(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.submit_queue.read().await.last() {
            Some(b) => Ok(Some(b.clone())),
            None => self.read_blocks().await.last_verified(),
        }
    }

    async fn add_block(&self, hb: HashedBlock) -> Result<(), ApiError> {
        let mut blockchain = self.blockchain.write().await;
        blockchain.block_store.mark_last_verified(hb.index)?;
        blockchain.add_block(hb)
    }
}

impl Default for TestLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LedgerAccess for TestLedger {
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a> {
        Box::new(self.blockchain.read().await)
    }

    async fn cleanup(&self) {}

    fn token_symbol(&self) -> &str {
        DEFAULT_TOKEN_SYMBOL
    }

    async fn sync_blocks(&self, _stopped: Arc<AtomicBool>) -> Result<(), ApiError> {
        let mut queue = self.submit_queue.write().await;

        {
            let mut blockchain = self.blockchain.write().await;
            for hb in queue.iter() {
                blockchain.block_store.mark_last_verified(hb.index)?;
                blockchain.add_block(hb.clone())?;
            }
        }

        *queue = Vec::new();

        Ok(())
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn governance_canister_id(&self) -> &CanisterId {
        &self.governance_canister_id
    }

    async fn submit(&self, envelopes: SignedTransaction) -> Result<TransactionResults, ApiError> {
        let mut results = vec![];

        for (request_type, request) in &envelopes {
            assert_eq!(request_type, &RequestType::Send);

            let EnvelopePair { update, .. } = &request[0];

            let HttpCanisterUpdate { arg, sender, .. } = match update.content.clone() {
                HttpCallContent::Call { update } => update,
            };

            let from = PrincipalId::try_from(sender.0)
                .map_err(|e| ApiError::internal_error(format!("{}", e)))?;

            let SendArgs {
                memo,
                amount,
                fee,
                from_subaccount,
                to,
                created_at_time,
            } = from_arg(arg.0).unwrap();
            let created_at_time = created_at_time.unwrap();

            let from = ledger_canister::AccountIdentifier::new(from, from_subaccount);

            let transaction = Operation::Transfer {
                from,
                to,
                amount,
                fee,
            };

            let (parent_hash, index) = match self.last_submitted().await? {
                None => (None, 0),
                Some(hb) => (Some(hb.hash), hb.index + 1),
            };

            let block = Block::new(
                None, /* FIXME */
                transaction.clone(),
                memo,
                created_at_time,
                dfn_core::api::now().into(),
            )
            .map_err(ApiError::internal_error)?;

            let raw_block = block.clone().encode().map_err(ApiError::internal_error)?;

            let hb = HashedBlock::hash_block(raw_block, parent_hash, index);

            self.submit_queue.write().await.push(hb.clone());

            results.push(RequestResult {
                _type: Request::Transfer(transaction),
                transaction_identifier: Some(From::from(&block.transaction().hash())),
                block_index: None,
                neuron_id: None,
                status: Status::Completed,
                response: None,
            });
        }

        Ok(results.into())
    }

    async fn neuron_info(
        &self,
        _id: NeuronIdOrSubaccount,
        _: bool,
    ) -> Result<ic_nns_governance::pb::v1::NeuronInfo, ApiError> {
        panic!("Neuron info not available through TestLedger");
    }

    async fn transfer_fee(&self) -> Result<TransferFee, ApiError> {
        Ok(TransferFee {
            transfer_fee: self.transfer_fee,
        })
    }
}

pub(crate) fn to_balances(
    b: BTreeMap<AccountIdentifier, Tokens>,
    index: BlockHeight,
) -> BalanceBook {
    let mut balance_book = BalanceBook::default();
    for (acc, amount) in b {
        balance_book.token_pool -= amount;
        balance_book.store.insert(acc, index, amount);
    }
    balance_book
}

pub async fn get_balance(
    req_handler: &RosettaRequestHandler,
    height: Option<usize>,
    acc: AccountIdentifier,
) -> Result<Tokens, ApiError> {
    let block_id = height.map(|h| PartialBlockIdentifier {
        index: Some(h as i64),
        hash: None,
    });
    let mut msg =
        AccountBalanceRequest::new(req_handler.network_id(), to_model_account_identifier(&acc));
    msg.block_identifier = block_id;
    let resp = req_handler.account_balance(msg).await?;
    Ok(Tokens::from_e8s(resp.balances[0].value.parse().unwrap()))
}
