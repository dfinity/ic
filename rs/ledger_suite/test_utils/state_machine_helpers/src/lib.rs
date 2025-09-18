use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_http_types::{HttpRequest, HttpResponse};
use ic_icrc1::{Block, endpoints::StandardRecord};
use ic_ledger_core::Tokens;
use ic_ledger_core::block::{BlockIndex, BlockType};
use ic_ledger_core::tokens::TokensType;
use ic_management_canister_types_private::{
    CanisterInfoRequest, CanisterInfoResponse, Method, Payload,
};
use ic_state_machine_tests::{StateMachine, WasmResult};
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm};
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs, IcpAllowanceArgs};
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc2::allowance::{Allowance, AllowanceArgs};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use icrc_ledger_types::icrc3::archive::ArchiveInfo;
use icrc_ledger_types::icrc3::blocks::{
    BlockRange, GetBlocksRequest, GetBlocksResponse, GetBlocksResult, SupportedBlockType,
};
use icrc_ledger_types::icrc3::transactions::GetTransactionsRequest;
use icrc_ledger_types::icrc3::transactions::GetTransactionsResponse;
use icrc_ledger_types::icrc3::transactions::Transaction as Tx;
use icrc_ledger_types::icrc3::transactions::TransactionRange;
use icrc_ledger_types::icrc21::errors::Icrc21Error;
use icrc_ledger_types::icrc21::requests::ConsentMessageRequest;
use icrc_ledger_types::icrc21::responses::ConsentInfo;
use num_traits::ToPrimitive;
use std::str::FromStr;
use std::{collections::BTreeMap, time::Duration};

pub trait AllowanceProvider: Sized {
    fn get_allowance(
        env: &StateMachine,
        ledger: CanisterId,
        account: impl Into<Self>,
        spender: impl Into<Self>,
    ) -> Allowance;
}

impl AllowanceProvider for Account {
    fn get_allowance(
        env: &StateMachine,
        ledger: CanisterId,
        account: impl Into<Account>,
        spender: impl Into<Account>,
    ) -> Allowance {
        let arg = AllowanceArgs {
            account: account.into(),
            spender: spender.into(),
        };
        Decode!(
            &env.query(ledger, "icrc2_allowance", Encode!(&arg).unwrap())
                .expect("failed to guery the allowance")
                .bytes(),
            Allowance
        )
        .expect("failed to decode allowance response")
    }
}

impl AllowanceProvider for AccountIdentifier {
    fn get_allowance(
        env: &StateMachine,
        ledger: CanisterId,
        account: impl Into<AccountIdentifier>,
        spender: impl Into<AccountIdentifier>,
    ) -> Allowance {
        let arg = IcpAllowanceArgs {
            account: account.into(),
            spender: spender.into(),
        };
        Decode!(
            &env.query(ledger, "allowance", Encode!(&arg).unwrap())
                .expect("failed to guery the allowance")
                .bytes(),
            Allowance
        )
        .expect("failed to decode allowance response")
    }
}

pub trait BalanceProvider: Sized {
    fn get_balance(env: &StateMachine, ledger: CanisterId, account: impl Into<Self>) -> Nat;
}

impl BalanceProvider for Account {
    fn get_balance(env: &StateMachine, ledger: CanisterId, account: impl Into<Account>) -> Nat {
        Decode!(
            &env.query(
                ledger,
                "icrc1_balance_of",
                Encode!(&account.into()).unwrap()
            )
            .expect("failed to query balance")
            .bytes(),
            Nat
        )
        .expect("failed to decode icrc1_balance_of response")
    }
}

impl BalanceProvider for AccountIdentifier {
    fn get_balance(
        env: &StateMachine,
        ledger: CanisterId,
        account: impl Into<AccountIdentifier>,
    ) -> Nat {
        let arg = BinaryAccountBalanceArgs {
            account: account.into().to_address(),
        };
        Decode!(
            &env.query(ledger, "account_balance", Encode!(&arg).unwrap())
                .expect("failed to guery balance")
                .bytes(),
            Tokens
        )
        .expect("failed to decode account_balance response")
        .get_e8s()
        .into()
    }
}

pub fn balance_of(env: &StateMachine, ledger: CanisterId, acc: impl Into<Account>) -> u64 {
    Decode!(
        &env.query(ledger, "icrc1_balance_of", Encode!(&acc.into()).unwrap())
            .expect("failed to query balance")
            .bytes(),
        Nat
    )
    .expect("failed to decode balance_of response")
    .0
    .to_u64()
    .unwrap()
}

pub fn fee(env: &StateMachine, ledger: CanisterId) -> u64 {
    Decode!(
        &env.query(ledger, "icrc1_fee", Encode!().unwrap())
            .expect("failed to query fee")
            .bytes(),
        Nat
    )
    .expect("failed to decode icrc1_fee response")
    .0
    .to_u64()
    .unwrap()
}

pub fn get_all_ledger_and_archive_blocks<Tokens: TokensType>(
    state_machine: &StateMachine,
    ledger_id: CanisterId,
    start_index: Option<u64>,
    num_blocks: Option<u64>,
) -> Vec<Block<Tokens>> {
    let start_index = start_index.unwrap_or(0);
    let num_blocks = num_blocks.unwrap_or(u32::MAX as u64);
    let req = GetBlocksRequest {
        start: icrc_ledger_types::icrc1::transfer::BlockIndex::from(start_index),
        length: Nat::from(num_blocks),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = state_machine
        .query(ledger_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res = Decode!(&res, GetBlocksResponse).expect("Failed to decode GetBlocksResponse");
    // Assume that all blocks in the ledger can be retrieved in a single call. This should hold for
    // most tests.
    let blocks_in_ledger = res
        .chain_length
        .saturating_sub(res.first_index.0.to_u64().unwrap());
    assert!(
        blocks_in_ledger <= res.blocks.len() as u64,
        "Chain length: {}, first block index: {}, retrieved blocks: {}",
        res.chain_length,
        res.first_index,
        res.blocks.len()
    );
    let mut blocks = vec![];
    for archived in res.archived_blocks {
        let mut remaining = archived.length.clone();
        let mut next_archived_txid = archived.start.clone();
        while remaining > 0u32 {
            let req = GetTransactionsRequest {
                start: next_archived_txid.clone(),
                length: remaining.clone(),
            };
            let req =
                Encode!(&req).expect("Failed to encode GetTransactionsRequest for archive node");
            let canister_id = archived.callback.canister_id;
            let res = state_machine
                .query(
                    CanisterId::unchecked_from_principal(PrincipalId(canister_id)),
                    archived.callback.method.clone(),
                    req,
                )
                .expect("Failed to send get_blocks request to archive")
                .bytes();
            let res = Decode!(&res, BlockRange).unwrap();
            next_archived_txid += res.blocks.len() as u64;
            remaining -= res.blocks.len() as u32;
            blocks.extend(res.blocks);
        }
    }
    blocks.extend(res.blocks);
    blocks
        .into_iter()
        .map(ic_icrc1::Block::try_from)
        .collect::<Result<Vec<Block<Tokens>>, String>>()
        .expect("should convert generic blocks to ICRC1 blocks")
}

pub fn get_archive_blocks(
    env: &StateMachine,
    archive: Principal,
    start: u64,
    length: usize,
) -> BlockRange {
    get_transactions_as(env, archive, start, length, "get_blocks".to_string())
}

pub fn get_archive_remaining_capacity(env: &StateMachine, archive: Principal) -> u64 {
    let canister_id = CanisterId::unchecked_from_principal(archive.into());
    Decode!(
        &env.query(canister_id, "remaining_capacity", Encode!().unwrap())
            .expect("failed to get archive remaining capacity")
            .bytes(),
        u64
    )
    .expect("failed to decode remaining_capacity response")
}

pub fn get_archive_transaction(
    env: &StateMachine,
    archive: Principal,
    block_index: u64,
) -> Option<Tx> {
    let canister_id = CanisterId::unchecked_from_principal(archive.into());
    Decode!(
        &env.query(
            canister_id,
            "get_transaction",
            Encode!(&block_index).unwrap()
        )
        .expect("failed to get transaction")
        .bytes(),
        Option<Tx>
    )
    .expect("failed to decode get_transaction response")
}

pub fn get_archive_transactions(
    env: &StateMachine,
    archive: Principal,
    start: u64,
    length: usize,
) -> TransactionRange {
    get_transactions_as(env, archive, start, length, "get_transactions".to_string())
}

pub fn get_blocks(
    env: &StateMachine,
    archive: Principal,
    start: u64,
    length: usize,
) -> GetBlocksResponse {
    get_transactions_as(env, archive, start, length, "get_blocks".to_string())
}

pub fn get_canister_info(
    env: &StateMachine,
    ucan: CanisterId,
    canister_id: CanisterId,
) -> Result<CanisterInfoResponse, String> {
    let info_request_payload = universal_canister_payload(
        &PrincipalId::default(),
        &Method::CanisterInfo.to_string(),
        CanisterInfoRequest::new(canister_id, None).encode(),
        Cycles::new(0),
    );
    let wasm_result = env
        .execute_ingress(ucan, "update", info_request_payload)
        .unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => Ok(CanisterInfoResponse::decode(&bytes[..])
            .expect("failed to decode canister_info response")),
        WasmResult::Reject(reason) => Err(reason),
    }
}

pub fn get_transactions(
    env: &StateMachine,
    archive: Principal,
    start: u64,
    length: usize,
) -> GetTransactionsResponse {
    get_transactions_as(env, archive, start, length, "get_transactions".to_string())
}

pub fn icrc3_get_blocks(
    env: &StateMachine,
    canister_id: CanisterId,
    start: u64,
    length: usize,
) -> GetBlocksResult {
    Decode!(
        &env.query(
            canister_id,
            "icrc3_get_blocks",
            Encode!(&vec![GetTransactionsRequest {
                start: Nat::from(start),
                length: Nat::from(length)
            }])
            .unwrap()
        )
        .expect("failed to query ledger blocks")
        .bytes(),
        GetBlocksResult
    )
    .expect("failed to decode icrc3_get_blocks response")
}

pub fn icrc21_consent_message(
    env: &StateMachine,
    ledger: CanisterId,
    caller: Principal,
    consent_msg_request: ConsentMessageRequest,
) -> Result<ConsentInfo, Icrc21Error> {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(caller),
            ledger, "icrc21_canister_call_consent_message", Encode!(&consent_msg_request).unwrap())
            .expect("failed to query icrc21_consent_message")
            .bytes(),
            Result<ConsentInfo, Icrc21Error>
    )
    .expect("failed to decode icrc21_canister_call_consent_message response")
}

pub fn list_archives(env: &StateMachine, ledger: CanisterId) -> Vec<ArchiveInfo> {
    Decode!(
        &env.query(ledger, "archives", Encode!().unwrap())
            .expect("failed to query archives")
            .bytes(),
        Vec<ArchiveInfo>
    )
    .expect("failed to decode archives response")
}

pub fn metadata(env: &StateMachine, ledger: CanisterId) -> BTreeMap<String, Value> {
    Decode!(
        &env.query(ledger, "icrc1_metadata", Encode!().unwrap())
            .expect("failed to query metadata")
            .bytes(),
        Vec<(String, Value)>
    )
    .expect("failed to decode metadata response")
    .into_iter()
    .collect()
}

pub fn minting_account(env: &StateMachine, ledger: CanisterId) -> Option<Account> {
    Decode!(
        &env.query(ledger, "icrc1_minting_account", Encode!().unwrap())
            .expect("failed to query minting account icrc1")
            .bytes(),
        Option<Account>
    )
    .expect("failed to decode icrc1_minting_account response")
}

pub fn parse_metric(env: &StateMachine, canister_id: CanisterId, metric: &str) -> u64 {
    let metrics = retrieve_metrics(env, canister_id);
    for line in &metrics {
        let tokens: Vec<&str> = line.split(' ').collect();
        let name = *tokens
            .first()
            .unwrap_or_else(|| panic!("metric line '{line}' should have at least one token"));
        if name != metric {
            continue;
        }
        let value_str = *tokens
            .get(1)
            .unwrap_or_else(|| panic!("metric line '{line}' should have at least two tokens"));
        let u64_value = f64::from_str(value_str)
            .unwrap_or_else(|err| panic!("metric value is not an number: {line} ({err})"))
            .round() as u64;
        return u64_value;
    }
    panic!("metric '{metric}' not found in metrics: {metrics:?}");
}

pub fn retrieve_metrics(env: &StateMachine, canister_id: CanisterId) -> Vec<String> {
    let request = HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: Default::default(),
        body: Default::default(),
    };
    let result = env
        .query(
            canister_id,
            "http_request",
            Encode!(&request).expect("failed to encode HTTP request"),
        )
        .expect("should successfully query canister for metrics");
    let reply = match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("expected a successful reply, got a reject: {reject}")
        }
    };
    let response = Decode!(&reply, HttpResponse).expect("should successfully decode HttpResponse");
    assert_eq!(response.status_code, 200_u16);
    String::from_utf8_lossy(response.body.as_slice())
        .trim()
        .split('\n')
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
}

pub fn send_approval(
    env: &StateMachine,
    ledger: CanisterId,
    from: Principal,
    arg: &ApproveArgs,
) -> Result<BlockIndex, ApproveError> {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(from),
            ledger,
            "icrc2_approve",
            Encode!(arg)
            .unwrap()
        )
        .expect("failed to apply approval")
        .bytes(),
        Result<Nat, ApproveError>
    )
    .expect("failed to decode approve response")
    .map(|n| n.0.to_u64().unwrap())
}

pub fn send_transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: Principal,
    arg: &TransferArg,
) -> Result<BlockIndex, TransferError> {
    let response = env.execute_ingress_as(
        PrincipalId(from),
        ledger,
        "icrc1_transfer",
        Encode!(arg).unwrap(),
    );
    Decode!(
        &response
        .expect("failed to transfer funds")
        .bytes(),
        Result<Nat, TransferError>
    )
    .expect("failed to decode transfer response")
    .map(|n| n.0.to_u64().unwrap())
}

pub fn send_transfer_from(
    env: &StateMachine,
    ledger: CanisterId,
    from: Principal,
    arg: &TransferFromArgs,
) -> Result<BlockIndex, TransferFromError> {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(from),
            ledger,
            "icrc2_transfer_from",
            Encode!(arg)
            .unwrap()
        )
        .expect("failed to apply approval")
        .bytes(),
        Result<Nat, TransferFromError>
    )
    .expect("failed to decode transfer_from response")
    .map(|n| n.0.to_u64().unwrap())
}

pub fn supported_block_types(env: &StateMachine, ledger: CanisterId) -> Vec<SupportedBlockType> {
    Decode!(
        &env.query(ledger, "icrc3_supported_block_types", Encode!().unwrap())
            .expect("failed to query supported standards")
            .bytes(),
        Vec<SupportedBlockType>
    )
    .expect("failed to decode icrc3_supported_block_types response")
}

pub fn supported_standards(env: &StateMachine, ledger: CanisterId) -> Vec<StandardRecord> {
    Decode!(
        &env.query(ledger, "icrc1_supported_standards", Encode!().unwrap())
            .expect("failed to query supported standards")
            .bytes(),
        Vec<StandardRecord>
    )
    .expect("failed to decode icrc1_supported_standards response")
}

pub fn total_supply(env: &StateMachine, ledger: CanisterId) -> u64 {
    Decode!(
        &env.query(ledger, "icrc1_total_supply", Encode!().unwrap())
            .expect("failed to query total supply")
            .bytes(),
        Nat
    )
    .expect("failed to decode totalSupply response")
    .0
    .to_u64()
    .unwrap()
}

pub fn transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: impl Into<Account>,
    to: impl Into<Account>,
    amount: u64,
) -> Result<BlockIndex, TransferError> {
    let from = from.into();
    send_transfer(
        env,
        ledger,
        from.owner,
        &TransferArg {
            from_subaccount: from.subaccount,
            to: to.into(),
            fee: None,
            created_at_time: None,
            amount: Nat::from(amount),
            memo: None,
        },
    )
}

pub fn wait_ledger_ready(env: &StateMachine, ledger: CanisterId, num_waits: u16) {
    let is_ledger_ready = || {
        Decode!(
            &env.query(ledger, "is_ledger_ready", Encode!().unwrap())
                .expect("failed to call is_ledger_ready")
                .bytes(),
            bool
        )
        .expect("failed to decode is_ledger_ready response")
    };
    for i in 0..num_waits {
        if is_ledger_ready() {
            println!("ready after {i} waits");
            return;
        }
        env.advance_time(Duration::from_secs(10));
        env.tick();
    }
    if !is_ledger_ready() {
        panic!("canister not ready!");
    }
}

fn get_transactions_as<Response: CandidType + for<'a> candid::Deserialize<'a>>(
    env: &StateMachine,
    canister: Principal,
    start: u64,
    length: usize,
    method_name: String,
) -> Response {
    let canister_id = CanisterId::unchecked_from_principal(canister.into());
    Decode!(
        &env.query(
            canister_id,
            method_name,
            Encode!(&GetTransactionsRequest {
                start: Nat::from(start),
                length: Nat::from(length)
            })
            .unwrap()
        )
        .expect("failed to query ledger transactions")
        .bytes(),
        Response
    )
    .expect("failed to decode get_transactions response")
}

fn universal_canister_payload(
    receiver: &PrincipalId,
    method: &str,
    payload: Vec<u8>,
    cycles: Cycles,
) -> Vec<u8> {
    wasm()
        .call_with_cycles(
            receiver,
            method,
            call_args()
                .other_side(payload)
                .on_reject(wasm().reject_message().reject()),
            cycles,
        )
        .build()
}
