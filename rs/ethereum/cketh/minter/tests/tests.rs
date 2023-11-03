use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_cdk::api::management_canister::http_request::{
    HttpResponse as OutCallHttpResponse, TransformArgs,
};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::events::{
    Event, EventPayload, EventSource, GetEventsResult, TransactionReceipt, TransactionStatus,
    UnsignedTransaction,
};
use ic_cketh_minter::endpoints::RetrieveEthStatus::Pending;
use ic_cketh_minter::endpoints::{
    EthTransaction, RetrieveEthRequest, RetrieveEthStatus, TxFinalizedStatus, WithdrawalArg,
    WithdrawalError,
};
use ic_cketh_minter::lifecycle::{init::InitArg as MinterInitArgs, EthereumNetwork, MinterArg};
use ic_cketh_minter::logs::Log;
use ic_cketh_minter::numeric::BlockNumber;
use ic_cketh_minter::{
    PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, PROCESS_REIMBURSEMENT, SCRAPPING_ETH_LOGS_INTERVAL,
};
use ic_icrc1_ledger::{InitArgsBuilder as LedgerInitArgsBuilder, LedgerArgument};
use ic_state_machine_tests::{
    CanisterHttpRequestContext, CanisterHttpResponsePayload, Cycles, MessageId, PayloadBuilder,
    StateMachine, StateMachineBuilder, WasmResult,
};
use ic_test_utilities_load_wasm::load_wasm;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use num_traits::cast::ToPrimitive;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

const CKETH_TRANSFER_FEE: u64 = 10;
const MAX_TICKS: usize = 10;
const DEFAULT_PRINCIPAL_ID: u64 = 10352385;
const DEFAULT_DEPOSIT_BLOCK_NUMBER: u64 = 0x9;
const DEFAULT_DEPOSIT_FROM_ADDRESS: &str = "0x55654e7405fcb336386ea8f36954a211b2cda764";
const DEFAULT_DEPOSIT_TRANSACTION_HASH: &str =
    "0xcfa48c44dc89d18a898a42b4a5b02b6847a3c2019507d5571a481751c7a2f353";
const DEFAULT_DEPOSIT_LOG_INDEX: u64 = 0x24;
const DEFAULT_BLOCK_HASH: &str =
    "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4";
const DEFAULT_BLOCK_NUMBER: u64 = 0x4132ec;
const EXPECTED_BALANCE: u64 = 100_000_000_000_000_000;
const EFFECTIVE_GAS_PRICE: u64 = 4_277_923_390;

const DEFAULT_WITHDRAWAL_TRANSACTION_HASH: &str =
    "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5";

#[test]
fn should_deposit_and_withdraw() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);
    let destination = "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0".to_string();

    let cketh = cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), destination.clone())
        .expect_withdrawal_request_accepted();

    let withdrawal_id = cketh.withdrawal_id().clone();
    let cketh = cketh.wait_and_validate_withdrawal(
        "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string(),
        true,
    );
    assert_eq!(cketh.balance_of(caller), Nat::from(0));

    let max_fee_per_gas = Nat::from(33003708258u64);
    let gas_limit = Nat::from(21_000);

    cketh.assert_has_unique_events_in_order(&vec![
        EventPayload::AcceptedEthWithdrawalRequest {
            withdrawal_amount: withdrawal_amount.clone(),
            destination: destination.clone(),
            ledger_burn_index: withdrawal_id.clone(),
            from: caller,
            from_subaccount: None,
        },
        EventPayload::CreatedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            transaction: UnsignedTransaction {
                chain_id: Nat::from(1),
                nonce: Nat::from(0),
                max_priority_fee_per_gas: Nat::from(1_500_000_000),
                max_fee_per_gas: max_fee_per_gas.clone(),
                gas_limit: gas_limit.clone(),
                destination,
                value: withdrawal_amount - max_fee_per_gas * gas_limit,
                data: Default::default(),
                access_list: vec![],
            },
        },
        EventPayload::SignedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            raw_transaction: "0x02f87301808459682f008507af2c9f6282520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c0880160cf1e9917a0e680c001a0b27af25a08e87836a778ac2858fdfcff1f6f3a0d43313782c81d05ca34b80271a078026b399a32d3d7abab625388a3c57f651c66a182eb7f8b1a58d9aef7547256".to_string(),
        },
        EventPayload::FinalizedTransaction {
            withdrawal_id,
            transaction_receipt: TransactionReceipt {
                block_hash: DEFAULT_BLOCK_HASH.to_string(),
                block_number: Nat::from(DEFAULT_BLOCK_NUMBER),
                effective_gas_price: Nat::from(4277923390u64),
                gas_used: Nat::from(21_000),
                status: TransactionStatus::Success,
                transaction_hash:
                "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string(),
            },
        },
    ]);
}

#[test]
fn should_block_deposit_from_blocked_address() {
    let cketh = CkEthSetup::new();
    let from_address_blocked: Address = "0x01e2919679362dFBC9ee1644Ba9C6da6D6245BB1"
        .parse()
        .unwrap();

    cketh
        .deposit(DepositParams {
            from_address: from_address_blocked,
            ..Default::default()
        })
        .expect_no_mint()
        .assert_has_unique_events_in_order(&vec![EventPayload::InvalidDeposit {
            event_source: EventSource {
                transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
            },
            reason: format!("blocked address {from_address_blocked}"),
        }]);
}

#[test]
fn should_block_withdrawal_to_blocked_address() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);
    let blocked_address = "0x01e2919679362dFBC9ee1644Ba9C6da6D6245BB1".to_string();

    cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), blocked_address.clone())
        .expect_error(WithdrawalError::RecipientAddressBlocked {
            address: blocked_address,
        });
}

#[test]
fn should_reimburse() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);
    let destination = "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0".to_string();

    let cketh = cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None);

    let balance_before_withdrawal = cketh.setup.balance_of(caller);
    assert_eq!(balance_before_withdrawal, withdrawal_amount);

    let cketh = cketh
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), destination.clone())
        .expect_withdrawal_request_accepted();

    let withdrawal_id = cketh.withdrawal_id().clone();
    let cketh = cketh.wait_and_validate_withdrawal(
        "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string(),
        false,
    );

    assert_eq!(cketh.balance_of(caller), Nat::from(0));

    cketh.env.advance_time(PROCESS_REIMBURSEMENT);
    cketh.env.tick();

    let gas_cost = Nat::from(21_000_u64 * EFFECTIVE_GAS_PRICE);
    let balance_after_withdrawal = cketh.balance_of(caller);
    assert_eq!(
        balance_after_withdrawal,
        balance_before_withdrawal.clone() - gas_cost.clone()
    );

    let withdrawal_status = cketh.retrieve_eth_status(withdrawal_id.0.to_u64().unwrap());
    assert_eq!(
        withdrawal_status,
        RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Reimbursed {
            reimbursed_amount: balance_before_withdrawal.clone() - gas_cost.clone(),
            reimbursed_in_block: withdrawal_id.clone() + 1,
            transaction_hash: "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5"
                .to_string(),
        })
    );

    let max_fee_per_gas = Nat::from(33003708258u64);
    let gas_limit = Nat::from(21_000);

    cketh.assert_has_unique_events_in_order(&vec![
        EventPayload::AcceptedEthWithdrawalRequest {
            withdrawal_amount: withdrawal_amount.clone(),
            destination: destination.clone(),
            ledger_burn_index: withdrawal_id.clone(),
            from: caller,
            from_subaccount: None,
        },
        EventPayload::CreatedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            transaction: UnsignedTransaction {
                chain_id: Nat::from(1),
                nonce: Nat::from(0),
                max_priority_fee_per_gas: Nat::from(1_500_000_000),
                max_fee_per_gas: max_fee_per_gas.clone(),
                gas_limit: gas_limit.clone(),
                destination,
                value: withdrawal_amount - max_fee_per_gas * gas_limit,
                data: Default::default(),
                access_list: vec![],
            },
        },
        EventPayload::SignedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            raw_transaction: "0x02f87301808459682f008507af2c9f6282520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c0880160cf1e9917a0e680c001a0b27af25a08e87836a778ac2858fdfcff1f6f3a0d43313782c81d05ca34b80271a078026b399a32d3d7abab625388a3c57f651c66a182eb7f8b1a58d9aef7547256".to_string(),
        },
        EventPayload::FinalizedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            transaction_receipt: TransactionReceipt {
                block_hash: DEFAULT_BLOCK_HASH.to_string(),
                block_number: Nat::from(DEFAULT_BLOCK_NUMBER),
                effective_gas_price: Nat::from(4277923390u64),
                gas_used: Nat::from(21_000),
                status: TransactionStatus::Failure,
                transaction_hash:
                "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string(),
            }},
        EventPayload::ReimbursedEthWithdrawal {
            reimbursed_amount: balance_before_withdrawal - gas_cost,
            withdrawal_id: withdrawal_id.clone(),
            reimbursed_in_block: withdrawal_id + 1,
        },
    ]);
}

#[test]
fn two_log_scrappings_should_not_overlap() {
    let mut cketh = CkEthSetup::new();

    assert_eq!(
        "0xfD644A761079369962386f8E4259217C2a10B8D0".to_string(),
        cketh.minter_address()
    );

    cketh.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    tick_until_next_http_request(&cketh.env, "eth_getBlockByNumber");
    cketh.handle_rpc_call(
        "https://rpc.ankr.com/eth",
        "eth_getBlockByNumber",
        eth_get_block_by_number(DEFAULT_BLOCK_NUMBER),
    );
    cketh.handle_rpc_call(
        "https://cloudflare-eth.com",
        "eth_getBlockByNumber",
        eth_get_block_by_number(DEFAULT_BLOCK_NUMBER),
    );
    cketh.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    tick_until_next_http_request(&cketh.env, "eth_getLogs");

    let (first_from_block, first_to_block) = cketh.get_scrap_logs_range();
    assert_eq!(first_from_block, BlockNumber::from(3_956_207_u64));
    assert_eq!(first_to_block, BlockNumber::from(3_957_007_u64));

    cketh.handle_rpc_call(
        "https://rpc.ankr.com/eth",
        "eth_getLogs",
        eth_get_logs(None),
    );
    cketh.handle_rpc_call(
        "https://cloudflare-eth.com",
        "eth_getLogs",
        eth_get_logs(None),
    );

    tick_until_next_http_request(&cketh.env, "eth_getLogs");
    let (from_block, to_block) = cketh.get_scrap_logs_range();
    assert_eq!(
        from_block,
        first_to_block
            .checked_add(BlockNumber::from(1_u64))
            .unwrap()
    );
    assert_eq!(
        to_block,
        from_block.checked_add(BlockNumber::from(800_u64)).unwrap()
    );
}

fn assert_contains_unique_event(events: &[Event], payload: EventPayload) {
    match events.iter().filter(|e| e.payload == payload).count() {
        0 => panic!("missing the event payload {payload:#?} in audit log {events:#?}"),
        1 => (),
        n => panic!("event payload {payload:#?} appears {n} times in audit log {events:#?}"),
    }
}

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("Expected a successful reply, got a reject: {}", reject)
        }
    }
}

fn parse_json_value(json_str: &str, json_name: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json_str).ok()?;
    match value.get(json_name) {
        Some(method) => method.as_str().map(|s| s.to_string()),
        None => None,
    }
}

fn ledger_wasm() -> Vec<u8> {
    let path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rosetta-api")
        .join("icrc1")
        .join("ledger");
    load_wasm(path, "ic-icrc1-ledger", &[])
}

fn minter_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "cketh_minter",
        &[],
    )
}

fn install_minter(env: &StateMachine, ledger_id: CanisterId, minter_id: CanisterId) -> CanisterId {
    let args = MinterInitArgs {
        ecdsa_key_name: "master_ecdsa_public_key".parse().unwrap(),
        ethereum_network: EthereumNetwork::Mainnet,
        ledger_id: ledger_id.get().0,
        next_transaction_nonce: 0.into(),
        ethereum_block_height: Default::default(),
        ethereum_contract_address: Some("0x907b6EFc1a398fD88A8161b3cA02eEc8Eaf72ca1".to_string()),
        minimum_withdrawal_amount: 1.into(),
        last_scraped_block_number: 3_956_206.into(),
    };
    let minter_arg = MinterArg::InitArg(args);
    env.install_existing_canister(minter_id, minter_wasm(), Encode!(&minter_arg).unwrap())
        .unwrap();
    minter_id
}

fn assert_has_header(req: &CanisterHttpRequestContext, name: &str, value: &str) {
    assert!(req
        .headers
        .iter()
        .any(|h| h.name == name && h.value == value));
}

fn default_deposit_from_address() -> Address {
    DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap()
}

#[derive(Clone)]
struct EthLogEntry {
    encoded_principal: String,
    amount: u64,
    from_address: Address,
    transaction_hash: String,
}

fn eth_get_logs(log_entry: Option<EthLogEntry>) -> Vec<u8> {
    let content: Vec<Value> = vec![];
    let mut result: Value = json!(content);
    if let Some(log_entry) = log_entry {
        let amount_hex = format!("0x{:0>64x}", log_entry.amount);
        result = json!([{
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": "0x79cfe76d69337dae199e32c2b6b3d7c2668bfe71a05f303f95385e70031b9ef8",
            "blockNumber": format!("0x{:x}", DEFAULT_DEPOSIT_BLOCK_NUMBER),
            "data": amount_hex,
            "logIndex": format!("0x{:x}", DEFAULT_DEPOSIT_LOG_INDEX),
            "removed": false,
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                format!("0x000000000000000000000000{}", hex::encode(log_entry.from_address.as_ref())),
                log_entry.encoded_principal
            ],
            "transactionHash": log_entry.transaction_hash,
            "transactionIndex": "0x33"
        }]);
    }

    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 141,
        "result": result
    }))
    .expect("Failed to serialize JSON")
}

fn eth_get_fee_history() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "result": {
            "oldestBlock": "0x1134b57",
            "reward": [
                ["0x25ed41c"],
                ["0x0"],
                ["0x0"],
                ["0x479ace"],
                ["0x0"]
            ],
            "baseFeePerGas": [
                "0x39fc781e8",
                "0x3ab9a6343",
                "0x3a07c507e",
                "0x39814c872",
                "0x391ea51f7",
                "0x3aae23831"
            ]
        },
        "id": 0
    }))
    .expect("Failed to serialize JSON")
}

fn eth_send_raw_transaction() -> Vec<u8> {
    serde_json::to_vec(&json!({"id":1,"jsonrpc":"2.0","result":"0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d"}))
        .expect("Failed to serialize JSON")
}

fn eth_get_block_by_number(block_number: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc":"2.0",
        "result":{
            "number": format!("{:#x}", block_number),
            "baseFeePerGas":"0x3e4f64de7"
        },
        "id":1
    }))
    .expect("Failed to serialize JSON")
}

fn eth_get_transaction_receipt(
    transaction_hash: String,
    status: bool,
    effective_gas_price: u64,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
    "jsonrpc":"2.0",
    "id":1,
    "result":{
     "blockHash": DEFAULT_BLOCK_HASH,
        "blockNumber": format!("{:#x}", DEFAULT_BLOCK_NUMBER),
        "contractAddress": null,
        "cumulativeGasUsed": "0x8b2e10",
        "effectiveGasPrice": format!("{:#x}", effective_gas_price),
        "from": "0x1789f79e95324a47c5fd6693071188e82e9a3558",
        "gasUsed": "0x5208",
        "logs": [],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status": format!("{:#x}", status as u8),
        "to": "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0",
        "transactionHash": transaction_hash,
        "transactionIndex": "0x32",
        "type": "0x2"
        }}))
    .expect("Failed to serialize JSON")
}

fn eth_get_transaction_count(count: u32) -> Vec<u8> {
    let hex_count = format!("{:#x}", count);
    serde_json::to_vec(&json!({
    "jsonrpc":"2.0",
    "id":1,
    "result": hex_count}))
    .expect("Failed to serialize JSON")
}

fn encode_principal(principal: Principal) -> String {
    let n = principal.as_slice().len();
    assert!(n <= 29);
    let mut fixed_bytes = [0u8; 32];
    fixed_bytes[0] = n as u8;
    fixed_bytes[1..=n].copy_from_slice(principal.as_slice());
    format!("0x{}", hex::encode(fixed_bytes))
}

fn tick_until_next_http_request(env: &StateMachine, method: &str) {
    for _ in 0..MAX_TICKS {
        for context in env.canister_http_request_contexts().values() {
            assert_has_header(context, "Content-Type", "application/json");
            let parsed_method = parse_json_value(
                std::str::from_utf8(&context.body.clone().unwrap()).unwrap(),
                "method",
            )
            .unwrap();
            if parsed_method == method {
                break;
            }
        }
        env.tick();
        env.advance_time(Duration::from_nanos(1));
    }
    assert!(
        !env.canister_http_request_contexts().is_empty(),
        "The canister did not produce another request in {} ticks",
        MAX_TICKS
    );
}

struct CkEthSetup {
    pub env: StateMachine,
    pub caller: PrincipalId,
    pub ledger_id: CanisterId,
    pub minter_id: CanisterId,
}

impl CkEthSetup {
    pub fn new() -> Self {
        let env = StateMachineBuilder::new()
            .with_default_canister_range()
            .build();
        let minter_id =
            env.create_canister_with_cycles(None, Cycles::new(100_000_000_000_000), None);
        let ledger_id = env.create_canister(None);

        env.install_existing_canister(
            ledger_id,
            ledger_wasm(),
            Encode!(&LedgerArgument::Init(
                LedgerInitArgsBuilder::with_symbol_and_name("ckETH", "ckETH")
                    .with_minting_account(minter_id.get().0)
                    .with_transfer_fee(CKETH_TRANSFER_FEE)
                    .with_max_memo_length(80)
                    .with_decimals(18)
                    .with_feature_flags(ic_icrc1_ledger::FeatureFlags { icrc2: true })
                    .build(),
            ))
            .unwrap(),
        )
        .unwrap();
        let minter_id = install_minter(&env, ledger_id, minter_id);
        let caller = PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID);

        Self {
            env,
            caller,
            ledger_id,
            minter_id,
        }
    }

    pub fn deposit(self, params: DepositParams) -> DepositFlow {
        assert_eq!(
            "0xfD644A761079369962386f8E4259217C2a10B8D0".to_string(),
            self.minter_address()
        );
        DepositFlow {
            setup: self,
            params,
        }
    }

    pub fn handle_rpc_call(&mut self, provider: &str, method: &str, response_body: Vec<u8>) {
        let mut payload = PayloadBuilder::new();
        let contexts = self.env.canister_http_request_contexts();
        for (id, context) in &contexts {
            assert_has_header(context, "Content-Type", "application/json");
            let parsed_method = parse_json_value(
                std::str::from_utf8(&context.body.clone().unwrap()).unwrap(),
                "method",
            )
            .unwrap();
            let url = &context.url.clone();
            if url == provider && parsed_method == method {
                let clean_up_context = match context.transform.clone() {
                    Some(transform) => transform.context,
                    None => vec![],
                };
                let transform_arg = TransformArgs {
                    response: OutCallHttpResponse {
                        status: 200.into(),
                        headers: vec![],
                        body: response_body.clone(),
                    },
                    context: clean_up_context.to_vec(),
                };
                let clean_up_response = self.cleanup_response(transform_arg);
                let http_response = CanisterHttpResponsePayload {
                    status: 200_u128,
                    headers: vec![],
                    body: clean_up_response.body,
                };
                payload = payload.http_response(*id, &http_response);
                self.env.execute_payload(payload);
                return;
            }
        }
        panic!("no http request found that match parameters: provider: {provider} and method: {method}");
    }

    pub fn minter_address(&self) -> String {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "minter_address",
                        Encode!().unwrap(),
                    )
                    .expect("failed to get eth address")
            ),
            String
        )
        .unwrap()
    }

    pub fn retrieve_eth_status(&self, block_index: u64) -> RetrieveEthStatus {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "retrieve_eth_status",
                        Encode!(&block_index).unwrap(),
                    )
                    .expect("failed to get eth address")
            ),
            RetrieveEthStatus
        )
        .unwrap()
    }

    pub fn balance_of(&self, account: impl Into<Account>) -> Nat {
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.ledger_id,
                        "icrc1_balance_of",
                        Encode!(&account.into()).unwrap()
                    )
                    .expect("failed to query balance on the ledger")
            ),
            Nat
        )
        .unwrap()
    }

    pub fn call_ledger_approve_minter(
        self,
        from: Principal,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> ApprovalFlow {
        let approval_id = Decode!(&assert_reply(self.env.execute_ingress_as(
            PrincipalId::from(from),
            self.ledger_id,
            "icrc2_approve",
            Encode!(&ApproveArgs {
                from_subaccount,
                spender: Account {
                    owner: self.minter_id.into(),
                    subaccount: None
                },
                amount: Nat::from(amount),
                expected_allowance: None,
                expires_at: None,
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()
            ).expect("failed to execute token transfer")),
            Result<Nat, ApproveError>
        )
        .unwrap()
        .expect("approve failed");
        ApprovalFlow {
            setup: self,
            _approval_id: approval_id,
        }
    }

    pub fn _get_logs(&self, priority: &str) -> Log {
        let request = HttpRequest {
            method: "".to_string(),
            url: format!("/logs?priority={priority}"),
            headers: vec![],
            body: serde_bytes::ByteBuf::new(),
        };
        let response = Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "http_request", Encode!(&request).unwrap(),)
                    .expect("failed to get minter info")
            ),
            HttpResponse
        )
        .unwrap();
        serde_json::from_slice(&response.body).expect("failed to parse ckbtc minter log")
    }

    pub fn cleanup_response(&self, args: TransformArgs) -> OutCallHttpResponse {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(self.minter_id, "cleanup_response", Encode!(&args).unwrap(),)
                    .expect("failed to query transform http response")
            ),
            OutCallHttpResponse
        )
        .unwrap()
    }

    pub fn assert_has_unique_events_in_order(self, expected_events: &[EventPayload]) -> Self {
        let audit_events = self.get_all_events();
        let mut found_event_indexes = BTreeMap::new();
        for (index_expected_event, expected_event) in expected_events.iter().enumerate() {
            for (index_audit_event, audit_event) in audit_events.iter().enumerate() {
                if &audit_event.payload == expected_event {
                    assert_eq!(
                        found_event_indexes.insert(index_expected_event, index_audit_event),
                        None,
                        "Event {:?} occurs multiple times",
                        expected_event
                    );
                }
            }
            assert!(
                found_event_indexes.contains_key(&index_expected_event),
                "Missing event {:?}",
                expected_event
            )
        }
        let audit_event_indexes = found_event_indexes.into_values().collect::<Vec<_>>();
        let sorted_audit_event_indexes = {
            let mut indexes = audit_event_indexes.clone();
            indexes.sort_unstable();
            indexes
        };
        assert_eq!(
            audit_event_indexes, sorted_audit_event_indexes,
            "Events were found in unexpected order"
        );
        self
    }

    fn get_events(&self, start: u64, length: u64) -> GetEventsResult {
        use ic_cketh_minter::endpoints::events::GetEventsArg;

        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(
                        self.minter_id,
                        "get_events",
                        Encode!(&GetEventsArg { start, length }).unwrap(),
                    )
                    .expect("failed to get minter info")
            ),
            GetEventsResult
        )
        .unwrap()
    }

    pub fn get_all_events(&self) -> Vec<Event> {
        const FIRST_BATCH_SIZE: u64 = 100;
        let GetEventsResult {
            mut events,
            total_event_count,
        } = self.get_events(0, FIRST_BATCH_SIZE);
        while events.len() < total_event_count as usize {
            let mut next_batch =
                self.get_events(events.len() as u64, total_event_count - events.len() as u64);
            events.append(&mut next_batch.events);
        }
        events
    }

    fn get_scrap_logs_range(&self) -> (BlockNumber, BlockNumber) {
        let method = "eth_getLogs";
        let contexts = self.env.canister_http_request_contexts();
        for context in contexts.values() {
            assert_has_header(context, "Content-Type", "application/json");
            let parsed_method = parse_json_value(
                std::str::from_utf8(&context.body.clone().unwrap()).unwrap(),
                "method",
            )
            .unwrap();

            if parsed_method == method {
                use ic_cketh_minter::eth_rpc::{BlockSpec, GetLogsParam, JsonRpcRequest};

                let status = serde_json::from_slice::<JsonRpcRequest<Vec<GetLogsParam>>>(
                    &context.body.clone().unwrap().clone(),
                )
                .unwrap();
                let from_block = match &status.params[0].from_block {
                    BlockSpec::Number(block_number) => *block_number,
                    BlockSpec::Tag(_) => {
                        panic!()
                    }
                };
                let to_block = match &status.params[0].to_block {
                    BlockSpec::Number(block_number) => *block_number,
                    BlockSpec::Tag(_) => {
                        panic!()
                    }
                };
                return (from_block, to_block);
            }
        }
        panic!("couldn't find any eth_getLogs request");
    }

    fn check_audit_log(&self) {
        Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "check_audit_log", Encode!().unwrap())
                    .unwrap(),
            ),
            ()
        )
        .unwrap()
    }

    fn upgrade_minter(&self) {
        self.env
            .upgrade_canister(
                self.minter_id,
                minter_wasm(),
                Encode!(&MinterArg::UpgradeArg(Default::default())).unwrap(),
            )
            .unwrap();
    }
}

struct DepositParams {
    pub from_address: Address,
    pub recipient: Principal,
    pub amount: u64,
}

impl Default for DepositParams {
    fn default() -> Self {
        Self {
            from_address: default_deposit_from_address(),
            recipient: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
            amount: EXPECTED_BALANCE,
        }
    }
}

struct DepositFlow {
    setup: CkEthSetup,
    params: DepositParams,
}

impl DepositFlow {
    pub fn expect_mint(mut self) -> CkEthSetup {
        let balance_before = self.setup.balance_of(self.params.recipient);
        self.handle_deposit();
        let balance_after: Nat = self.updated_balance(&balance_before);
        assert_eq!(balance_after - balance_before, self.params.amount);

        self.setup.check_audit_log();

        let events = self.setup.get_all_events();
        assert_contains_unique_event(
            &events,
            EventPayload::AcceptedDeposit {
                transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                block_number: Nat::from(DEFAULT_DEPOSIT_BLOCK_NUMBER),
                log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                from_address: self.params.from_address.to_string(),
                value: Nat::from(self.params.amount),
                principal: self.params.recipient,
            },
        );
        assert_contains_unique_event(
            &events,
            EventPayload::MintedCkEth {
                event_source: EventSource {
                    transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                    log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                },
                mint_block_index: Nat::from(0),
            },
        );
        self.setup
    }

    fn updated_balance(&self, balance_before: &Nat) -> Nat {
        let mut current_balance = balance_before.clone();
        for _ in 0..10 {
            self.setup.env.advance_time(Duration::from_secs(1));
            self.setup.env.tick();
            current_balance = self.setup.balance_of(self.params.recipient);
            if &current_balance != balance_before {
                break;
            }
        }
        current_balance
    }

    pub fn expect_no_mint(mut self) -> CkEthSetup {
        let balance_before = self.setup.balance_of(self.params.recipient);
        self.handle_deposit();
        let balance_after: Nat = self.updated_balance(&balance_before);
        assert_eq!(balance_before, balance_after);
        self.setup
    }

    fn handle_deposit(&mut self) {
        let encoded_principal = encode_principal(self.params.recipient);

        self.setup.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
        tick_until_next_http_request(&self.setup.env, "eth_getBlockByNumber");
        self.setup.handle_rpc_call(
            "https://rpc.ankr.com/eth",
            "eth_getBlockByNumber",
            eth_get_block_by_number(DEFAULT_BLOCK_NUMBER),
        );
        self.setup.handle_rpc_call(
            "https://cloudflare-eth.com",
            "eth_getBlockByNumber",
            eth_get_block_by_number(DEFAULT_BLOCK_NUMBER),
        );
        self.setup.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
        tick_until_next_http_request(&self.setup.env, "eth_getLogs");

        let log_entry = EthLogEntry {
            encoded_principal: encoded_principal.clone(),
            amount: self.params.amount,
            from_address: self.params.from_address,
            transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
        };
        self.setup.handle_rpc_call(
            "https://rpc.ankr.com/eth",
            "eth_getLogs",
            eth_get_logs(Some(log_entry.clone())),
        );
        self.setup.handle_rpc_call(
            "https://cloudflare-eth.com",
            "eth_getLogs",
            eth_get_logs(Some(log_entry)),
        );
    }
}

struct ApprovalFlow {
    setup: CkEthSetup,
    _approval_id: Nat,
}

impl ApprovalFlow {
    pub fn call_minter_withdraw_eth(
        self,
        from: Principal,
        amount: Nat,
        recipient: String,
    ) -> WithdrawalFlow {
        let arg = WithdrawalArg { amount, recipient };
        let message_id = self.setup.env.send_ingress(
            PrincipalId::from(from),
            self.setup.minter_id,
            "withdraw_eth",
            Encode!(&arg).expect("failed to encode withdraw args"),
        );
        WithdrawalFlow {
            setup: self.setup,
            message_id,
        }
    }
}

struct WithdrawalFlow {
    setup: CkEthSetup,
    message_id: MessageId,
}

impl WithdrawalFlow {
    pub fn expect_withdrawal_request_accepted(self) -> ProcessWithdrawal {
        let response = self
            .minter_response()
            .expect("BUG: unexpected error from minter during withdrawal");
        ProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: response,
        }
    }

    pub fn expect_error(self, error: WithdrawalError) -> CkEthSetup {
        assert_eq!(
            self.minter_response(),
            Err(error),
            "BUG: unexpected result during withdrawal"
        );
        self.setup
    }

    fn minter_response(&self) -> Result<RetrieveEthRequest, WithdrawalError> {
        Decode!(&assert_reply(
        self.setup.env
            .await_ingress(self.message_id.clone(), MAX_TICKS)
            .expect("failed to resolve message with id: {message_id}"),
    ), Result<RetrieveEthRequest, WithdrawalError>)
        .unwrap()
    }
}

struct ProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
}

impl ProcessWithdrawal {
    pub fn withdrawal_id(&self) -> &Nat {
        &self.withdrawal_request.block_index
    }

    pub fn wait_and_validate_withdrawal(
        mut self,
        transaction_hash: String,
        status: bool,
    ) -> CkEthSetup {
        let block_index = self.withdrawal_id().0.to_u64().unwrap();
        assert_eq!(self.setup.retrieve_eth_status(block_index), Pending);
        self.setup
            .env
            .advance_time(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL);
        tick_until_next_http_request(&self.setup.env, "eth_feeHistory");
        self.setup.handle_rpc_call(
            "https://rpc.ankr.com/eth",
            "eth_feeHistory",
            eth_get_fee_history(),
        );
        self.setup.handle_rpc_call(
            "https://cloudflare-eth.com",
            "eth_feeHistory",
            eth_get_fee_history(),
        );
        tick_until_next_http_request(&self.setup.env, "eth_getTransactionCount");
        self.setup.handle_rpc_call(
            "https://rpc.ankr.com/eth",
            "eth_getTransactionCount",
            eth_get_transaction_count(0),
        );
        self.setup.handle_rpc_call(
            "https://cloudflare-eth.com",
            "eth_getTransactionCount",
            eth_get_transaction_count(0),
        );

        assert_eq!(
            self.setup.retrieve_eth_status(block_index),
            RetrieveEthStatus::TxCreated
        );

        tick_until_next_http_request(&self.setup.env, "eth_sendRawTransaction");
        self.setup.handle_rpc_call(
            "https://rpc.ankr.com/eth",
            "eth_sendRawTransaction",
            eth_send_raw_transaction(),
        );

        assert_eq!(
            self.setup.retrieve_eth_status(block_index),
            RetrieveEthStatus::TxSent(EthTransaction { transaction_hash })
        );

        tick_until_next_http_request(&self.setup.env, "eth_getTransactionCount");
        self.setup.handle_rpc_call(
            "https://rpc.ankr.com/eth",
            "eth_getTransactionCount",
            eth_get_transaction_count(1),
        );
        self.setup.handle_rpc_call(
            "https://cloudflare-eth.com",
            "eth_getTransactionCount",
            eth_get_transaction_count(1),
        );

        tick_until_next_http_request(&self.setup.env, "eth_getTransactionReceipt");
        self.setup.handle_rpc_call(
            "https://rpc.ankr.com/eth",
            "eth_getTransactionReceipt",
            eth_get_transaction_receipt(
                DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
                status,
                EFFECTIVE_GAS_PRICE,
            ),
        );
        self.setup.handle_rpc_call(
            "https://cloudflare-eth.com",
            "eth_getTransactionReceipt",
            eth_get_transaction_receipt(
                DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
                status,
                EFFECTIVE_GAS_PRICE,
            ),
        );

        self.setup.check_audit_log();
        self.setup.env.tick(); //tick before upgrade to finish current timers which are reset afterwards
        self.setup.upgrade_minter();

        let retrieve_eth_status = self.setup.retrieve_eth_status(block_index);
        let eth_transaction = EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        };
        if status {
            assert_eq!(
                retrieve_eth_status,
                RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Success(eth_transaction))
            );
        } else {
            assert_eq!(
                retrieve_eth_status,
                RetrieveEthStatus::TxFinalized(TxFinalizedStatus::PendingReimbursement(
                    eth_transaction
                ))
            );
        }
        self.setup
    }
}
