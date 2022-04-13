mod setup;

use ic_ic00_types::{
    CanisterIdRecord, CanisterInstallMode, InstallCodeArgs, Method as Ic00Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs, IC_00,
};
use ic_interfaces::{execution_environment::IngressHistoryReader, messaging::MessageRouting};
use ic_interfaces_state_manager::{
    PermanentStateHashError::*, StateHashError, StateManager, StateReader,
    TransientStateHashError::*,
};
use ic_messaging::MessageRoutingImpl;
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::types::messages::SignedIngressBuilder;
use ic_types::{
    artifact::SignedIngress,
    batch::{Batch, BatchPayload, IngressPayload, SelfValidatingPayload, XNetPayload},
    ingress::{IngressStatus, WasmResult},
    messages::MessageId,
    time::UNIX_EPOCH,
    CanisterId, CryptoHashOfState, Randomness, RegistryVersion,
};
use setup::setup;
use std::{convert::TryFrom, sync::Arc, thread::sleep, time::Duration};
use wabt::wat2wasm;

fn build_batch(message_routing: &dyn MessageRouting, msgs: Vec<SignedIngress>) -> Batch {
    Batch {
        batch_number: message_routing.expected_batch_height(),
        requires_full_state_hash: false,
        payload: BatchPayload {
            ingress: IngressPayload::from(msgs),
            xnet: XNetPayload {
                stream_slices: Default::default(),
            },
            self_validating: SelfValidatingPayload::default(),
        },
        randomness: Randomness::from([0; 32]),
        ecdsa_subnet_public_key: None,
        registry_version: RegistryVersion::from(1),
        time: UNIX_EPOCH,
        consensus_responses: vec![],
    }
}

fn build_batch_with_full_state_hash(message_routing: &dyn MessageRouting) -> Batch {
    Batch {
        batch_number: message_routing.expected_batch_height(),
        requires_full_state_hash: true,
        payload: BatchPayload {
            ingress: IngressPayload::from(vec![]),
            xnet: XNetPayload {
                stream_slices: Default::default(),
            },
            self_validating: SelfValidatingPayload::default(),
        },
        randomness: Randomness::from([0; 32]),
        ecdsa_subnet_public_key: None,
        registry_version: RegistryVersion::from(1),
        time: UNIX_EPOCH,
        consensus_responses: vec![],
    }
}

fn deliver_batch(message_routing: &MessageRoutingImpl, batch: Batch) {
    const MAX_BATCHES_UNTIL_RESPONSE: u64 = 10000;
    for _ in 0..MAX_BATCHES_UNTIL_RESPONSE {
        if message_routing.deliver_batch(batch.clone()).is_ok() {
            return;
        }
    }
    panic!("failed to deliver batch after many retries");
}

fn wait_for_ingress_message(
    ingress_history_reader: &dyn IngressHistoryReader,
    message_id: MessageId,
) -> Vec<u8> {
    loop {
        let result = (ingress_history_reader.get_latest_status())(&message_id);
        match result {
            IngressStatus::Completed { result, .. } => match result {
                WasmResult::Reject(msg) => panic!("{}", msg),
                WasmResult::Reply(bytes) => return bytes,
            },
            IngressStatus::Failed { error, .. } => panic!("{:?}", error),
            IngressStatus::Done { .. } => {
                panic!("The call has completed but the reply/reject data has been pruned.")
            }
            IngressStatus::Received { .. }
            | IngressStatus::Processing { .. }
            | IngressStatus::Unknown => sleep(Duration::from_millis(5)),
        }
    }
}

fn execute_message(
    message_routing: &MessageRoutingImpl,
    ingress_history_reader: &dyn IngressHistoryReader,
    method_name: &str,
    canisters: &[CanisterId],
    mut nonce: u64,
) -> u64 {
    let msgs: Vec<SignedIngress> = canisters
        .iter()
        .map(|canister_id| {
            let msg = SignedIngressBuilder::new()
                .method_name(method_name)
                .canister_id(*canister_id)
                .nonce(nonce)
                .expiry_time(UNIX_EPOCH + Duration::from_secs(60))
                .build();
            nonce += 1;
            msg
        })
        .collect();
    let msg_ids: Vec<MessageId> = msgs.iter().map(|msg| msg.id()).collect();
    let batch = build_batch(message_routing, msgs);
    deliver_batch(message_routing, batch);

    for msg_id in msg_ids {
        wait_for_ingress_message(ingress_history_reader, msg_id);
    }
    nonce
}

fn get_state_hash(
    message_routing: &MessageRoutingImpl,
    state_manager: &Arc<StateManagerImpl>,
) -> CryptoHashOfState {
    deliver_batch(
        message_routing,
        build_batch_with_full_state_hash(message_routing),
    );
    loop {
        match state_manager.get_state_hash_at(state_manager.latest_state_height()) {
            Ok(hash) => {
                return hash;
            }
            Err(StateHashError::Transient(HashNotComputedYet(_)))
            | Err(StateHashError::Permanent(StateNotFullyCertified(_))) => {
                // Likely an issue with the test setup that `StateNotFullyCertified` is a
                // transient error in the context of this test
                sleep(Duration::from_millis(5))
            }
            Err(err) => {
                panic!("{:?}", err)
            }
        }
    }
}

fn install_canister(
    wasm: &str,
    message_routing: &MessageRoutingImpl,
    ingress_history_reader: &dyn IngressHistoryReader,
    mut nonce: u64,
) -> (CanisterId, u64) {
    let signed_ingress = SignedIngressBuilder::new()
        .method_name(Ic00Method::ProvisionalCreateCanisterWithCycles)
        .canister_id(IC_00)
        .method_payload(ProvisionalCreateCanisterWithCyclesArgs::new(None).encode())
        .expiry_time(UNIX_EPOCH + Duration::from_secs(60))
        .nonce(nonce)
        .build();
    nonce += 1;
    let message_id = signed_ingress.id();
    let batch = build_batch(message_routing, vec![signed_ingress]);
    deliver_batch(message_routing, batch);
    let bytes = wait_for_ingress_message(ingress_history_reader, message_id);
    let canister_id = match CanisterIdRecord::decode(bytes.as_slice()) {
        Ok(id) => id.get_canister_id(),
        Err(err) => panic!("{}", err),
    };

    let wasm = wat2wasm(wasm).unwrap();
    let signed_ingress = SignedIngressBuilder::new()
        .canister_id(IC_00)
        .expiry_time(UNIX_EPOCH + Duration::from_secs(60))
        .method_name(Ic00Method::InstallCode)
        .nonce(nonce)
        .method_payload(
            InstallCodeArgs::new(
                CanisterInstallMode::try_from("install".to_string()).unwrap(),
                canister_id,
                wasm,
                vec![],
                None,
                None,
                None,
            )
            .encode(),
        )
        .build();
    nonce += 1;
    let message_id = signed_ingress.id();
    let batch = build_batch(message_routing, vec![signed_ingress]);
    deliver_batch(message_routing, batch);
    loop {
        let result = (ingress_history_reader.get_latest_status())(&message_id);
        match result {
            IngressStatus::Completed { .. } => {
                break;
            }
            IngressStatus::Failed { error, .. } => panic!("{:?}", error),
            IngressStatus::Done { .. } => {
                panic!("The call has completed but the reply/reject data has been pruned.")
            }
            IngressStatus::Received { .. }
            | IngressStatus::Processing { .. }
            | IngressStatus::Unknown => sleep(Duration::from_millis(5)),
        }
    }
    (canister_id, nonce)
}

const WASM: &str = r#"(module
(import "ic0" "msg_reply" (func $msg_reply))

(func $dirty1
  (i32.store (i32.const 0) (i32.const 99))
  (call $msg_reply)
)

(func $dirty2
  (i32.store (i32.const 0) (i32.const 99))
  (i32.store (i32.const 4096) (i32.const 99))
  (call $msg_reply)
)

(memory $memory 1)
(export "canister_update dirty1" (func $dirty1))
(export "canister_update dirty2" (func $dirty2))
(export "memory" (memory $memory)))
"#;

pub fn determinism_test(msgs: Vec<&str>) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _enter_guard = rt.enter();
    let mut hashes = vec![];
    for i in 0..10 {
        println!("iteration {}", i);
        let mut nonce = 0;
        let (message_routing, state_manager, ingress_history_reader, _config, subnet_config) =
            setup();
        let num_canisters_per_core = 2;
        let canisters: Vec<CanisterId> = (0..subnet_config.scheduler_config.scheduler_cores
            * num_canisters_per_core)
            .map(|_index| {
                let (canister, inner_nonce) = install_canister(
                    WASM,
                    &message_routing,
                    ingress_history_reader.as_ref(),
                    nonce,
                );
                nonce = inner_nonce;
                canister
            })
            .collect();

        msgs.iter().fold(nonce, |nonce, msg| {
            execute_message(
                &message_routing,
                ingress_history_reader.as_ref(),
                msg,
                &canisters,
                nonce,
            )
        });

        let hash = get_state_hash(&message_routing, &state_manager);
        hashes.push(hash);
    }
    for window in hashes.windows(2) {
        assert_eq!(window[0], window[1]);
    }
}
