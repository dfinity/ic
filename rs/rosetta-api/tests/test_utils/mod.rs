use async_trait::async_trait;
use ic_ledger_canister_blocks_synchronizer::blocks::{Blocks, HashedBlock, RosettaBlocksMode};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::{block::BlockType, timestamp::TimeStamp};
use ic_nns_governance_api::pb::v1::{
    manage_neuron::NeuronIdOrSubaccount, KnownNeuron, ProposalInfo,
};
use ic_rosetta_api::{
    convert::{from_arg, to_model_account_identifier},
    errors::ApiError,
    ledger_client::LedgerAccess,
    models::{AccountBalanceRequest, EnvelopePair, PartialBlockIdentifier, SignedTransaction},
    request::{request_result::RequestResult, transaction_results::TransactionResults, Request},
    request_handler::RosettaRequestHandler,
    request_types::{RequestType, Status},
    DEFAULT_TOKEN_SYMBOL,
};
use ic_types::{
    messages::{HttpCallContent, HttpCanisterUpdate},
    CanisterId, PrincipalId,
};
use icp_ledger::{
    self, AccountIdentifier, Block, Operation, SendArgs, Tokens, TransferFee, DEFAULT_TRANSFER_FEE,
};
use std::{
    convert::TryFrom,
    ops::Deref,
    str::FromStr,
    sync::{atomic::AtomicBool, Arc, Mutex},
};
use tokio::sync::RwLock;

const FIRST_BLOCK_TIMESTAMP_NANOS_SINCE_EPOC: u64 = 1_656_147_600_000_000_000; // 25 June 2022 09:00:00

pub struct TestLedger {
    pub blockchain: RwLock<Blocks>,
    pub canister_id: CanisterId,
    pub governance_canister_id: CanisterId,
    pub submit_queue: RwLock<Vec<HashedBlock>>,
    pub transfer_fee: Tokens,
    pub next_block_timestamp: Mutex<TimeStamp>,
}

impl TestLedger {
    pub fn new() -> Self {
        Self {
            blockchain: RwLock::new(Blocks::new_in_memory(false).unwrap()),
            canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("5v3p4-iyaaa-aaaaa-qaaaa-cai").unwrap(),
            ),
            governance_canister_id: ic_nns_constants::GOVERNANCE_CANISTER_ID,
            submit_queue: RwLock::new(Vec::new()),
            transfer_fee: DEFAULT_TRANSFER_FEE,
            next_block_timestamp: Mutex::new(TimeStamp::from_nanos_since_unix_epoch(
                FIRST_BLOCK_TIMESTAMP_NANOS_SINCE_EPOC,
            )),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_blockchain(blocks: Blocks) -> Self {
        Self {
            blockchain: RwLock::new(blocks),
            ..Default::default()
        }
    }

    async fn last_submitted(&self) -> Result<HashedBlock, ApiError> {
        match self.submit_queue.read().await.last() {
            Some(b) => Ok(b.clone()),
            None => self
                .read_blocks()
                .await
                .get_latest_verified_hashed_block()
                .map_err(ApiError::from),
        }
    }

    pub(crate) async fn add_block(&self, hb: HashedBlock) -> Result<(), ApiError> {
        let mut blockchain = self.blockchain.write().await;
        blockchain.push(&hb).map_err(ApiError::from)?;
        blockchain
            .set_hashed_block_to_verified(&hb.index)
            .map_err(ApiError::from)
    }

    fn next_block_timestamp(&self) -> TimeStamp {
        let mut next_block_timestamp = self.next_block_timestamp.lock().unwrap();
        let res = *next_block_timestamp;
        *next_block_timestamp = next_millisecond(res);
        res
    }
}

// return a timestamp with +1 millisecond
fn next_millisecond(t: TimeStamp) -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(t.as_nanos_since_unix_epoch() + 1_000_000)
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

    async fn proposal_info(&self, _proposal_id: u64) -> Result<ProposalInfo, ApiError> {
        Err(ApiError::InternalError(false, Default::default()))
    }

    async fn list_known_neurons(&self) -> Result<Vec<KnownNeuron>, ApiError> {
        Err(ApiError::InternalError(false, Default::default()))
    }

    async fn pending_proposals(&self) -> Result<Vec<ProposalInfo>, ApiError> {
        Err(ApiError::InternalError(false, Default::default()))
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
                blockchain.push(hb)?;
                blockchain.set_hashed_block_to_verified(&hb.index)?;
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

    async fn submit(
        &self,
        signed_transaction: SignedTransaction,
    ) -> Result<TransactionResults, ApiError> {
        let mut results = vec![];

        for (request_type, request) in signed_transaction.requests.iter() {
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

            let from = icp_ledger::AccountIdentifier::new(from, from_subaccount);

            let transaction = Operation::Transfer {
                from,
                to,
                spender: None,
                amount,
                fee,
            };

            let (parent_hash, index) = match self.last_submitted().await.ok() {
                None => (None, 0),
                Some(hb) => (Some(hb.hash), hb.index + 1),
            };

            let timestamp = self.next_block_timestamp();

            let block = Block::new(
                parent_hash,
                transaction.clone(),
                memo,
                created_at_time,
                timestamp,
                DEFAULT_TRANSFER_FEE,
            )
            .map_err(ApiError::internal_error)?;

            let raw_block = block.clone().encode();

            let hb = HashedBlock::hash_block(raw_block, parent_hash, index, timestamp);

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
    ) -> Result<ic_nns_governance_api::pb::v1::NeuronInfo, ApiError> {
        panic!("Neuron info not available through TestLedger");
    }

    async fn transfer_fee(&self) -> Result<TransferFee, ApiError> {
        Ok(TransferFee {
            transfer_fee: self.transfer_fee,
        })
    }

    async fn rosetta_blocks_mode(&self) -> RosettaBlocksMode {
        RosettaBlocksMode::Disabled
    }
}

#[allow(dead_code)]
pub(crate) async fn get_balance(
    req_handler: &RosettaRequestHandler,
    height: Option<usize>,
    acc: AccountIdentifier,
) -> Result<Tokens, ApiError> {
    let block_id = height.map(|h| PartialBlockIdentifier {
        index: Some(h.try_into().unwrap()),
        hash: None,
    });

    let mut msg = AccountBalanceRequest {
        network_identifier: req_handler.network_id(),
        account_identifier: to_model_account_identifier(&acc),
        block_identifier: None,
        metadata: None,
    };

    msg.block_identifier = block_id;
    let resp = req_handler.account_balance(msg).await?;
    Ok(Tokens::from_e8s(resp.balances[0].value.parse().unwrap()))
}
