use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_management_canister_types::CanisterInfoArgs;
pub use ic_management_canister_types::{
    CanisterInfoResult, CanisterStatusType, ChangeDetails, CodeDeploymentMode, CodeDeploymentRecord,
};
use ic_types_cycles::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use pocket_ic::PocketIc;
use std::sync::Arc;

pub struct UniversalCanister {
    pub env: Arc<PocketIc>,
    pub canister_id: Principal,
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

    pub fn canister_info(&self, target: Principal) -> CanisterInfoResult {
        let info_request_payload = universal_canister_payload(
            Principal::management_canister(),
            "canister_info",
            Encode!(&CanisterInfoArgs {
                canister_id: target,
                num_requested_changes: Some(u64::MAX),
            })
            .unwrap(),
            Cycles::new(0),
        );
        let bytes = self
            .env
            .update_call(
                self.canister_id,
                Principal::anonymous(),
                "update",
                info_request_payload,
            )
            .unwrap();
        Decode!(&bytes[..], CanisterInfoResult).expect("failed to decode canister_info response")
    }
}

fn universal_canister_payload(
    receiver: Principal,
    method: &str,
    payload: Vec<u8>,
    cycles: Cycles,
) -> Vec<u8> {
    wasm()
        .call_with_cycles(
            PrincipalId(receiver),
            method,
            call_args()
                .other_side(payload)
                .on_reject(wasm().reject_message().reject()),
            cycles,
        )
        .build()
}
