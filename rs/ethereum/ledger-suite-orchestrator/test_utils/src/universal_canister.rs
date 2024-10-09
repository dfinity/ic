use crate::assert_reply;
use candid::Principal;
use ic_cdk::api::management_canister::main::CanisterId;
pub use ic_management_canister_types::{
    CanisterChangeDetails, CanisterInfoResponse, CanisterInstallMode,
};
use ic_management_canister_types::{CanisterInfoRequest, Method, Payload};
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use pocket_ic::PocketIc;
use std::sync::Arc;

pub struct UniversalCanister {
    pub env: Arc<PocketIc>,
    pub canister_id: CanisterId,
}

impl UniversalCanister {
    pub fn new(env: Arc<PocketIc>) -> Self {
        let canister_id = env.create_canister();
        env.add_cycles(canister_id, u128::MAX);
        Self { env, canister_id }.install_wasm()
    }

    fn install_wasm(self) -> Self {
        self.env.install_canister(
            self.canister_id,
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
        );
        self
    }

    pub fn canister_info(&self, target: CanisterId) -> CanisterInfoResponse {
        let info_request_payload = universal_canister_payload(
            &Principal::management_canister(),
            &Method::CanisterInfo.to_string(),
            CanisterInfoRequest::new(
                ic_base_types::CanisterId::try_from_principal_id(target.into()).unwrap(),
                Some(u64::MAX),
            )
            .encode(),
            0,
        );
        let bytes = assert_reply(
            self.env
                .update_call(
                    self.canister_id,
                    Principal::anonymous(),
                    "update",
                    info_request_payload,
                )
                .unwrap(),
        );
        CanisterInfoResponse::decode(&bytes[..]).expect("failed to decode canister_info response")
    }
}

fn universal_canister_payload(
    receiver: &Principal,
    method: &str,
    payload: Vec<u8>,
    cycles: u128,
) -> Vec<u8> {
    wasm()
        .call_with_cycles(
            receiver,
            method,
            call_args()
                .other_side(payload)
                .on_reject(wasm().reject_message().reject()),
            cycles.into(),
        )
        .build()
}
