use candid::{Decode, Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_http_types::{HttpRequest, HttpResponse};
use ic_icp_archive::ArchiveUpgradeArgument;
use ic_ledger_core::Tokens;
use ic_ledger_core::block::{BlockType, EncodedBlock};
use ic_ledger_core::timestamp::TimeStamp;
use icp_ledger::Operation::Mint;
use icp_ledger::{AccountIdentifier, Block, Memo, Transaction};
use pocket_ic::PocketIcBuilder;
use serde_bytes::ByteBuf;

const GENESIS_IN_NANOS_SINCE_UNIX_EPOCH: u64 = 1_620_328_630_000_000_000;

struct Setup {
    pocket_ic: pocket_ic::PocketIc,
    archive_canister_id: CanisterId,
    archive_wasm: Vec<u8>,
    canister_id: CanisterId,
}

impl Setup {
    fn new(archive_memory_size: u64) -> Setup {
        let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();
        let archive_wasm =
            std::fs::read(std::env::var("LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH").unwrap())
                .expect("Could not read archive wasm");
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
            archive_wasm.clone(),
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
            archive_wasm,
            canister_id,
        }
    }

    fn assert_remaining_capacity(&self, remaining_capacity: u64) {
        let result = self
            .pocket_ic
            .update_call(
                Principal::from(self.archive_canister_id),
                Principal::anonymous(),
                "remaining_capacity",
                Encode!(&()).expect("should encode empty args"),
            )
            .expect("failed to send remaining_capacity request");
        let res = Decode!(&result, u64).expect("failed to decode usize");
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

    fn upgrade(&self, upgrade_arg: Option<ArchiveUpgradeArgument>, expected_error: Option<String>) {
        let upgrade_arg = Encode!(&upgrade_arg).expect("should encode archive upgrade args");
        match self.pocket_ic.upgrade_canister(
            Principal::from(self.canister_id),
            self.archive_wasm.clone(),
            upgrade_arg,
            None,
        ) {
            Ok(_) => {
                if expected_error.is_some() {
                    panic!("Upgrade should fail!");
                }
            }
            Err(e) => {
                if let Some(error_msg) = expected_error {
                    assert!(e.reject_message.contains(&error_msg));
                } else {
                    panic!("Upgrade should succeed!");
                }
            }
        };
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
    setup.assert_remaining_capacity(archive_memory_size);
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
    let encoded_block_size = encoded_block.size_bytes() as u64;
    setup.append_block(encoded_block);
    setup.assert_remaining_capacity(archive_memory_size - encoded_block_size);
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
    let response_bytes = setup
        .pocket_ic
        .update_call(
            setup.archive_canister_id.into(),
            Principal::anonymous(),
            "http_request",
            http_request_bytes,
        )
        .unwrap();
    let response = Decode!(&response_bytes, HttpResponse).unwrap();
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
    assert!(
        err.reject_message
            .contains("Decoding cost exceeds the limit")
    );
}

#[test]
fn should_update_max_capacity_with_upgrade_arg() {
    let encoded_block = valid_encoded_block();
    let encoded_block_size = encoded_block.size_bytes() as u64;
    let setup = Setup::new(encoded_block_size + 7);
    setup.append_block(encoded_block.clone());
    setup.assert_remaining_capacity(7);

    setup.upgrade(None, None);
    setup.assert_remaining_capacity(7);

    let mut upgrade_arg = ArchiveUpgradeArgument {
        max_memory_size_bytes: None,
    };

    // Check upgrade arg without specifying the max capacity.
    setup.upgrade(Some(upgrade_arg.clone()), None);
    setup.assert_remaining_capacity(7);

    upgrade_arg.max_memory_size_bytes = Some(2 * encoded_block_size + 7);
    setup.upgrade(Some(upgrade_arg.clone()), None);
    setup.assert_remaining_capacity(encoded_block_size + 7);
    setup.append_block(encoded_block);
    setup.assert_remaining_capacity(7);

    upgrade_arg.max_memory_size_bytes = Some(encoded_block_size);
    setup.upgrade(
        Some(upgrade_arg.clone()),
        Some("Cannot set max_memory_size_bytes to".to_string()),
    );
    setup.assert_remaining_capacity(7);

    upgrade_arg.max_memory_size_bytes = Some(2 * encoded_block_size);
    setup.upgrade(Some(upgrade_arg.clone()), None);
    setup.assert_remaining_capacity(0);

    upgrade_arg.max_memory_size_bytes = Some(u64::MAX);
    setup.upgrade(Some(upgrade_arg), None);
    setup.assert_remaining_capacity(u64::MAX - 2 * encoded_block_size);
}
