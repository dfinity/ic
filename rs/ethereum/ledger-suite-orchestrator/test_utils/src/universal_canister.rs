use crate::assert_reply;
use ic_base_types::{CanisterId, PrincipalId};
pub use ic_management_canister_types::{
    CanisterChangeDetails, CanisterInfoResponse, CanisterInstallMode,
};
use ic_management_canister_types::{CanisterInfoRequest, Method, Payload};
use ic_state_machine_tests::StateMachine;
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use std::sync::Arc;

pub struct UniversalCanister {
    pub env: Arc<StateMachine>,
    pub canister_id: CanisterId,
}

impl UniversalCanister {
    pub fn new(env: Arc<StateMachine>) -> Self {
        let canister_id = env.create_canister_with_cycles(None, Cycles::new(u128::MAX), None);
        Self { env, canister_id }.install_wasm()
    }

    fn install_wasm(self) -> Self {
        self.env
            .install_existing_canister(self.canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), vec![])
            .unwrap();
        self
    }

    pub fn canister_info(&self, target: CanisterId) -> CanisterInfoResponse {
        let info_request_payload = universal_canister_payload(
            &PrincipalId::default(),
            &Method::CanisterInfo.to_string(),
            CanisterInfoRequest::new(target, Some(u64::MAX)).encode(),
            Cycles::new(0),
        );
        let bytes = assert_reply(
            self.env
                .execute_ingress(self.canister_id, "update", info_request_payload)
                .unwrap(),
        );
        CanisterInfoResponse::decode(&bytes[..]).expect("failed to decode canister_info response")
    }
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
