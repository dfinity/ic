use candid::{Decode, Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_ledger_core::block::{BlockType, EncodedBlock};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::Tokens;
use ic_ledger_test_utils::build_ledger_archive_wasm;
use icp_ledger::Operation::Mint;
use icp_ledger::{AccountIdentifier, Block, Memo, Transaction};
use pocket_ic::{PocketIcBuilder, WasmResult};
use serde_bytes::ByteBuf;

const GENESIS_IN_NANOS_SINCE_UNIX_EPOCH: u64 = 1_620_328_630_000_000_000;

struct Setup {
    pocket_ic: pocket_ic::PocketIc,
    archive_canister_id: CanisterId,
}

impl Setup {
    fn new(archive_memory_size: u64) -> Setup {
        let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();
        let archive_wasm = build_ledger_archive_wasm().bytes();
        let canister_id = CanisterId::from_u64(100);
        let created_canister_id = pocket_ic
            .create_canister_with_id(None, None, Principal::from(canister_id))
            .expect("should create canister successfully");
        assert_eq!(created_canister_id, Principal::from(canister_id));
        let node_block_height_offset = 0u64;
        let node_max_memory_size_bytes = archive_memory_size;
        let max_transactions_per_response = 10u64;
        pocket_ic.install_canister(
            Principal::from(canister_id),
            archive_wasm,
            Encode!(
                &canister_id,
                &node_block_height_offset,
                &Some(node_max_memory_size_bytes),
                &max_transactions_per_response
            )
            .expect("should encode archive init args"),
            None,
        );
        Setup {
            pocket_ic,
            archive_canister_id: canister_id,
        }
    }

    fn assert_remaining_capacity(&self, remaining_capacity: usize) {
        let result = self
            .pocket_ic
            .update_call(
                Principal::from(self.archive_canister_id),
                Principal::anonymous(),
                "remaining_capacity",
                Encode!(&()).expect("should encode empty args"),
            )
            .expect("failed to send remaining_capacity request");
        let result = match result {
            WasmResult::Reply(result) => result,
            WasmResult::Reject(s) => {
                panic!("Call to remaining_capacity failed: {:#?}", s)
            }
        };
        let res = Decode!(&result, usize).expect("failed to decode usize");
        assert_eq!(res, remaining_capacity);
    }

    fn append_block(&self, encoded_block: EncodedBlock) {
        let encoded_blocks = vec![encoded_block];
        self.pocket_ic
            .update_call(
                candid::Principal::from(self.archive_canister_id),
                candid::Principal::from(self.archive_canister_id),
                "append_blocks",
                Encode!(&encoded_blocks).expect("should encode vec![encoded_block]"),
            )
            .expect("failed to send append_blocks request");
    }
}

fn valid_encoded_block() -> EncodedBlock {
    let block = Block {
        parent_hash: None,
        transaction: Transaction {
            operation: Mint {
                to: AccountIdentifier::new(PrincipalId::new_user_test_id(1), None),
                amount: Tokens::from_e8s(100),
            },
            memo: Memo(45u64),
            created_at_time: None,
            icrc1_memo: None,
        },
        timestamp: TimeStamp::from_nanos_since_unix_epoch(GENESIS_IN_NANOS_SINCE_UNIX_EPOCH),
    };
    block.encode()
}

#[test]
fn should_return_initial_remaining_capacity_correctly() {
    let archive_memory_size = valid_encoded_block().size_bytes() as u64 + 1u64;
    let setup = Setup::new(archive_memory_size);
    setup.assert_remaining_capacity(archive_memory_size as usize);
}

#[test]
fn should_append_block() {
    let archive_memory_size = valid_encoded_block().size_bytes() as u64 + 1u64;
    let setup = Setup::new(archive_memory_size);
    let encoded_block = valid_encoded_block();
    assert!(encoded_block.size_bytes() < archive_memory_size as usize);
    setup.append_block(encoded_block);
}

#[test]
fn should_return_remaining_capacity_correctly_after_appending_block() {
    let archive_memory_size = valid_encoded_block().size_bytes() as u64 + 1u64;
    let setup = Setup::new(archive_memory_size);
    let encoded_block = valid_encoded_block();
    let encoded_block_size = encoded_block.size_bytes();
    setup.append_block(encoded_block);
    setup.assert_remaining_capacity(archive_memory_size as usize - encoded_block_size);
}

#[test]
#[should_panic(expected = "No space left")]
fn should_fail_to_append_block_when_insufficient_capacity() {
    let archive_memory_size = valid_encoded_block().size_bytes() as u64 - 1u64;
    let setup = Setup::new(archive_memory_size);
    let encoded_block = valid_encoded_block();
    let encoded_block_size = encoded_block.size_bytes();
    assert!(encoded_block_size > archive_memory_size as usize);
    setup.append_block(encoded_block);
}

#[test]
fn should_successfully_append_block_when_capacity_matches_block_size() {
    let archive_memory_size = valid_encoded_block().size_bytes() as u64;
    let setup = Setup::new(archive_memory_size);
    let encoded_block = valid_encoded_block();
    let encoded_block_size = encoded_block.size_bytes();
    assert_eq!(encoded_block_size, archive_memory_size as usize);
    setup.append_block(encoded_block);
}

#[test]
fn large_http_request() {
    let archive_memory_size = valid_encoded_block().size_bytes() as u64;
    let setup = Setup::new(archive_memory_size);

    // The anonymous end-user sends a small HTTP request. This should succeed.
    let http_request = HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: vec![],
        body: ByteBuf::from(vec![42; 1_000]),
    };
    let http_request_bytes = Encode!(&http_request).unwrap();
    let response = match setup
        .pocket_ic
        .update_call(
            setup.archive_canister_id.into(),
            Principal::anonymous(),
            "http_request",
            http_request_bytes,
        )
        .unwrap()
    {
        WasmResult::Reply(bytes) => Decode!(&bytes, HttpResponse).unwrap(),
        WasmResult::Reject(reason) => panic!("Unexpected reject: {}", reason),
    };
    assert_eq!(response.status_code, 200);

    // The anonymous end-user sends a large HTTP request. This should be rejected.
    let mut large_http_request = http_request;
    large_http_request.body = ByteBuf::from(vec![42; 1_000_000]);
    let large_http_request_bytes = Encode!(&large_http_request).unwrap();
    let err = setup
        .pocket_ic
        .update_call(
            setup.archive_canister_id.into(),
            Principal::anonymous(),
            "http_request",
            large_http_request_bytes,
        )
        .unwrap_err();
    assert!(err.description.contains("Deserialization Failed"));
}
