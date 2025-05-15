use candid::Principal;
use ic_cdk::call::{CallFailed, CallRejected, OnewayError};
use ic_call_chaos::{set_policy as cc_set_policy, Call, Policy};
use ic_call_retry::{when_out_of_time_or_stopping, Deadline};
use ic_cdk::update;
use ic_safe_upgrades::{upgrade_canister, upload_chunks, WasmModule, UpgradeStage, ChunkedModule};
use sha2::{Digest, Sha256};

#[update]
pub async fn try_upgrading_target(
    target_canister: Principal,
    new_wasm: Vec<u8>,
    deadline: u64,
    chunked: bool,
) -> Result<(), String> {
    let deadline = &mut when_out_of_time_or_stopping(&Deadline::TimeOrStopping(deadline));
    if chunked {
        let chunks: Vec<_> = new_wasm.chunks(1024 * 50).map(|c| c.to_vec()).collect();
        let hashes = chunks.iter().map(|c| Sha256::digest(c).to_vec()).collect();
        upload_chunks(
            target_canister,
            chunks,
            deadline,
        ).await
            .map_err(|e| format!("Failed to upload chunks: {:?}", e))?;

        let module = WasmModule::ChunkedModule(ChunkedModule {
            wasm_module_hash: Sha256::digest(&new_wasm).to_vec(),
            store_canister_id: target_canister,
            chunk_hashes_list: hashes,
        });
        upgrade_canister(
            target_canister,
            module,
            vec![],
            deadline,
        )
            .await
            .map_err(|e| format!("Failed to upgrade canister: {:?}", e))
    } else {
        upgrade_canister(
            target_canister,
            WasmModule::Bytes(new_wasm),
            vec![],
            deadline,
        )
        .await
            .map_err(|e| format!("Failed to upgrade canister: {:?}", e))
    }
}

struct FailAtStagePolicy {
    stage: UpgradeStage
}

impl FailAtStagePolicy {
    fn new(step: u32) -> Self {
        Self {
            stage: match step {
                0 => UpgradeStage::Stopping,
                1 => UpgradeStage::ObtainingInfo,
                2 => UpgradeStage::Installing,
                3 => UpgradeStage::Starting,
                _ => panic!("Invalid step {}", step),
            }
        }
    }
}

impl Policy for FailAtStagePolicy {
    fn allow(&mut self, call: &Call) -> Result<(), CallFailed> {
        let call_stage  = match call.method {
            "stop_canister" => Some(UpgradeStage::Stopping),
            "canister_info" => Some(UpgradeStage::ObtainingInfo),
            "install_code" => Some(UpgradeStage::Installing),
            "install_chunked_code" => Some(UpgradeStage::Installing),
            "start_canister" => Some(UpgradeStage::Starting),
            "clear_chunk_store" => None,
            "upload_chunk" => None,
            _ => panic!("Unknown method: {}", call.method),
        };
        if call_stage == Some(self.stage) {
            Err(CallFailed::CallRejected(CallRejected::with_rejection(2, "Simulate a transient failure".to_string())))
        } else {
            Ok(())
        }

    }

    fn allow_oneway(&mut self, _call: &Call) -> Result<(), Option<OnewayError>> {
        todo!()
    }
}


#[update]
pub async fn set_call_chaos_policy(policy: String) {
    match policy.as_str() {
        "AllowAll" => cc_set_policy(ic_call_chaos::AllowAll::default()),
        "AllowEveryOther" => cc_set_policy(ic_call_chaos::AllowEveryOther::default()),
        "DenyAll" => cc_set_policy(ic_call_chaos::DenyAll::default()),
        "WithProbability" => cc_set_policy(ic_call_chaos::WithProbability::new(0.1, 1337, true)),
        _ => panic!("Unknown policy: {}", policy),
    }
}

#[update]
pub async fn set_fail_at_stage_policy(step: u32) {
    cc_set_policy(FailAtStagePolicy::new(step));
}

fn main() {}
