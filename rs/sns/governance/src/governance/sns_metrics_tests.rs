use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Arc;

use super::test_helpers::{
    basic_governance_proto, canister_status_for_test,
    canister_status_from_management_canister_for_test, DoNothingLedger, TEST_ARCHIVES_CANISTER_IDS,
    TEST_GOVERNANCE_CANISTER_ID, TEST_INDEX_CANISTER_ID, TEST_LEDGER_CANISTER_ID,
    TEST_ROOT_CANISTER_ID, TEST_SWAP_CANISTER_ID,
};
use super::*;
use crate::sns_upgrade::CanisterSummary;
use crate::sns_upgrade::GetWasmRequest;
use crate::sns_upgrade::GetWasmResponse;
use crate::sns_upgrade::SnsWasm;
use crate::sns_upgrade::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use crate::{
    pb::v1::{
        governance::{CachedUpgradeSteps as CachedUpgradeStepsPb, Versions},
        upgrade_journal_entry::Event,
        GetUpgradeJournalRequest, ProposalData, Tally, UpgradeJournal, UpgradeJournalEntry,
        UpgradeSnsToNextVersion,
    },
    sns_upgrade::{ListUpgradeStep, ListUpgradeStepsRequest, ListUpgradeStepsResponse, SnsVersion},
    types::test_helpers::NativeEnvironment,
};
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusType,
};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use icrc_ledger_types::icrc3::blocks::GetBlocksResult;
use maplit::btreemap;
use pretty_assertions::assert_eq;

#[derive(Debug)]
enum LedgerCanisterClientCall {
    ICRC3Blocks {
        result: Result<GetBlocksResult, NervousSystemError>,
    },
}

#[derive(Debug, Clone)]
struct MockLedgerCanisterClient {
    calls: Arc<futures::lock::Mutex<VecDeque<LedgerCanisterClientCall>>>,
}

impl MockLedgerCanisterClient {
    fn new<T>(calls: T) -> Self
    where
        VecDeque<LedgerCanisterClientCall>: From<T>,
    {
        Self {
            calls: Arc::new(futures::lock::Mutex::new(VecDeque::<
                LedgerCanisterClientCall,
            >::from(calls))),
        }
    }
}

#[async_trait]
pub trait LedgerCanisterClient {
    async fn icrc3_get_blocks(&self) -> Result<GetBlocksResult, NervousSystemError>;
}

#[async_trait]
impl LedgerCanisterClient for MockLedgerCanisterClient {
    async fn icrc3_get_blocks(&self) -> Result<GetBlocksResult, NervousSystemError> {
        let mut calls = self.calls.lock().await;
        match calls.pop_front().unwrap() {
            LedgerCanisterClientCall::ICRC3Blocks { result } => result,
        }
    }
}

#[tokio::test]
async fn test_none_time_window() {
    // Step 1: Prepare the world.
    todo!()
}
