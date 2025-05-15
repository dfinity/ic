use candid::Principal;
use ic_call_retry::{
    call_idempotent_method_with_retry, call_nonidempotent_method_with_retry,
    ErrorCause, RetryError,
};
use ic_cdk::api::canister_self;
use ic_cdk::call::CallErrorExt;
use ic_cdk::management_canister::{
    CanisterInfoArgs, CanisterInfoResult, CanisterInstallMode, ChunkHash, ClearChunkStoreArgs,
    InstallCodeArgs, UploadChunkArgs,
};
use ic_management_canister_types::{ChangeDetails, ChangeOrigin, StartCanisterArgs, StopCanisterArgs, UploadChunkResult, InstallChunkedCodeArgs};
use sha2::{Digest, Sha256};

#[cfg(feature = "use_call_chaos")]
use ic_call_chaos::Call;
#[cfg(not(feature = "use_call_chaos"))]
use ic_cdk::call::Call;

/// Represents a canister's principal ID on the IC.
pub type CanisterId = Principal;

/// Describes the stage of the upgrade during which an error occurred
/// or after which we could not confirm status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeStage {
    Stopping,
    ObtainingInfo,
    Installing,
    Starting,
}

#[derive(Debug, Clone)]
pub enum UpgradeErrorReason {
    RetryError(RetryError),
    ConcurrentChangeDetected,
}

/// Errors returned by `upgrade_canister`.
#[derive(Debug, Clone)]
pub struct UpgradeError {
    pub stage: UpgradeStage,
    pub reason: UpgradeErrorReason,
}

/// Holds the meta-information needed for a chunked WASM install.
#[derive(Debug, Clone)]
pub struct ChunkedModule {
    /// SHA-256 hash of the entire WASM to be installed.
    pub wasm_module_hash: Vec<u8>,

    /// The canister storing the chunks (must be on the same subnet).
    pub store_canister_id: CanisterId,

    /// The list of chunk hashes that compose the WASM.
    pub chunk_hashes_list: Vec<Vec<u8>>,
}

/// The WASM to be installed.
#[derive(Debug, Clone)]
pub enum WasmModule {
    /// A module < 2MB that can be installed in a single message
    Bytes(Vec<u8>),
    /// A module > 2MB that must be installed in chunks. Chunks are assumed to already have been uploaded.
    ChunkedModule(ChunkedModule),
}

enum VersionChangeCheck {
    /// The version hasn't changed. The upgrade failed and can be retried.
    NoChange,
    /// The version has changed in the expected way. The upgrade succeeded.
    UpgradeSucceeded,
    /// A concurrent change was detected. The upgrade shouldn't be retried.
    ConcurrentChangeDetected,
}

async fn version_change_check(
    target_id: CanisterId,
    wasm_module: &WasmModule,
    old_version: u64,
    stop_trying: &mut impl FnMut() -> bool,
) -> Result<VersionChangeCheck, RetryError> {
    let (new_version, mut recent_changes) =
        bounded_wait_canister_info(target_id, Some(1), stop_trying)
            .await
            .map(|info| (info.total_num_changes, info.recent_changes))?;
    let last_change = if let Some(change) = recent_changes.pop() {
        change
    } else {
        // We asked for one recent change, and there really should be at least one,
        // since we're in the process of upgrading the canister. So there not being
        // a change should be unreachable, but possibly some very weird concurrent
        // changes are going on, so we can report that.
        return Ok(VersionChangeCheck::ConcurrentChangeDetected);
    };
    match (
        new_version - old_version,
        last_change.details,
        last_change.origin,
    ) {
        (0, _, _) => Ok(VersionChangeCheck::NoChange),
        (1, ChangeDetails::CodeDeployment(dep), ChangeOrigin::FromCanister(rec))
            if rec.canister_id == canister_self() =>
        {
            let expected_hash: Vec<u8> = match wasm_module {
                WasmModule::Bytes(ref wasm_bytes) => Sha256::digest(wasm_bytes).to_vec(),
                WasmModule::ChunkedModule(ref chunked) => chunked.wasm_module_hash.clone(),
            };
            if dep.module_hash != expected_hash {
                Ok(VersionChangeCheck::ConcurrentChangeDetected)
            } else {
                Ok(VersionChangeCheck::UpgradeSucceeded)
            }
        }
        (_, _, _) => Ok(VersionChangeCheck::ConcurrentChangeDetected),
    }
}

/// Safely upgrade a canister to a new version, without blocking the caller from
/// being upgraded itself.
///
/// Stops, installs, and then restarts the target canister.
/// Uses bounded-wait calls under the hood, ensuring that the caller isn't blocked
/// from upgrading itself due to open call contexts.
/// It retries any failed calls until the `stop_trying` function returns true.
/// See the `ic-call-retry` crate for sample functions.
///
/// In corner cases, it may be unknown whether the upgrade succeeded (as indicated by the
/// `StatusUnknown` return variant).
///
/// Note that this function cannot protect against concurrent upgrades of the target canister.
/// While it can detect concurrent updates in some cases (and return an error), the detection
/// is not bulletproof. It's the caller's responsibility to ensure that they are the sole
/// initiator of target canister upgrades, and that this function is not called multiple times in
/// parallel.
///
/// # Procedure
///
/// 1. **Stop** the canister C via a bounded-wait call (`SysUnknown` => retry).
///    - Because `stop_canister` is idempotent, we can safely retry until definite success.
/// 2. **Obtain** the current version (`canister_info`) to record the old WASM hash and canister
///    version.
/// 3. **Upgrade** the canister. If `SysUnknown` is returned, call `canister_info` again:
///    - If the canister's version changed by 1 and the hash is the expected one, we know the upgrade went through.
///    - If not, we retry or eventually give up as `StatusUnknown`.
/// 4. **Start** the canister again, also with bounded-wait calls.
///
/// # Returns
/// * `Ok(())` if we can confirm a successful upgrade.
/// * `Err(UpgradeError::UpgradeFailed(...))` if the upgrade failed definitively.
/// * `Err(UpgradeError::StatusUnknown(...))` if we cannot confirm success or failure.
pub async fn upgrade_canister<P>(
    target_id: CanisterId,
    wasm_module: WasmModule,
    arg: Vec<u8>,
    stop_trying: &mut P,
) -> Result<(), UpgradeError>
where
    P: FnMut() -> bool,
{
    // Converts a `BestEffortError` into an `UpgradeError` at a given stage.
    let add_stage = |stage: UpgradeStage| {
        move |error: RetryError| UpgradeError {
            stage,
            reason: UpgradeErrorReason::RetryError(error),
        }
    };

    // 1) Stop the canister (bounded-wait).
    bounded_wait_stop(target_id, stop_trying)
        .await
        .map_err(add_stage(UpgradeStage::Stopping))?;

    // 2) Query the current canister version for reference.
    let version = bounded_wait_canister_info(target_id, None, stop_trying)
        .await
        .map(|info| info.total_num_changes)
        .map_err(add_stage(UpgradeStage::ObtainingInfo))?;

    // 3) Install (upgrade) the new WASM. Loop until success or timeout. We can't retry directly
    // here if we don't know what happened, since installation isn't idempotent. Instead, use the
    // version number to determine if the upgrade went through.
    loop {
        let install_result = match wasm_module {
            WasmModule::Bytes(ref wasm_bytes) => {
                bounded_wait_install_single_chunk(target_id, wasm_bytes, &arg, stop_trying).await
            }
            WasmModule::ChunkedModule(ref chunked) => {
                bounded_wait_install_chunked(target_id, chunked, &arg, stop_trying).await
            }
        };

        match install_result {
            Ok(()) => break,
            // Note that for installation, unretriable errors include `SysUnknown`
            // Try to figure out what happened using the version and retry if the version
            // hasn't moved
            Err(RetryError::StatusUnknown(ErrorCause::CallFailed(rejection)))
                if !rejection.is_clean_reject() =>
            {
                let version_check_result =
                    version_change_check(target_id, &wasm_module, version, stop_trying)
                        .await
                        .map_err(add_stage(UpgradeStage::Installing))?;

                match version_check_result {
                    VersionChangeCheck::NoChange => {
                        ic_cdk::println!(
                            "Failed to upgrade {:?} and the version hasn't moved, retrying",
                            target_id
                        );
                        continue;
                    }
                    VersionChangeCheck::UpgradeSucceeded => {
                        break;
                    }
                    VersionChangeCheck::ConcurrentChangeDetected => {
                        return Err(UpgradeError {
                            stage: UpgradeStage::Installing,
                            reason: UpgradeErrorReason::ConcurrentChangeDetected,
                        });
                    }
                }
            }
            Err(error) => return Err(add_stage(UpgradeStage::Installing)(error)),
        }
    }

    bounded_wait_start(target_id, stop_trying)
        .await
        .map_err(add_stage(UpgradeStage::Starting))
}

/// Stop a canister with best-effort calls until success or timeout.
async fn bounded_wait_stop<P>(target_id: Principal, stop_trying: &mut P) -> Result<(), RetryError>
where
    P: FnMut() -> bool,
{
    let args = StopCanisterArgs {
        canister_id: target_id,
    };
    Ok(call_idempotent_method_with_retry(
        Call::bounded_wait(Principal::management_canister(), "stop_canister").with_arg(&args),
        stop_trying,
    )
    .await?
    .candid()
    .unwrap())
}

/// Start a canister with best-effort calls until success or timeout.
async fn bounded_wait_start<P>(target_id: CanisterId, stop_trying: &mut P) -> Result<(), RetryError>
where
    P: FnMut() -> bool,
{
    let args = StartCanisterArgs {
        canister_id: target_id,
    };
    Ok(call_idempotent_method_with_retry(
        Call::bounded_wait(Principal::management_canister(), "start_canister").with_arg(&args),
        stop_trying,
    )
    .await?
    .candid()
    .unwrap())
}

/// Retrieve canister info (including module hash) with best-effort calls.
async fn bounded_wait_canister_info<P>(
    target_id: CanisterId,
    num_requested_changes: Option<u64>,
    stop_trying: &mut P,
) -> Result<CanisterInfoResult, RetryError>
where
    P: FnMut() -> bool,
{
    let arg = CanisterInfoArgs {
        canister_id: target_id,
        num_requested_changes,
    };

    Ok(call_idempotent_method_with_retry(
        Call::bounded_wait(Principal::management_canister(), "canister_info").with_arg(&arg),
        stop_trying,
    )
    .await?
    .candid()
    .unwrap())
}

/// Install a small (<2MB) WASM in a single call via `install_code`.
/// Since code installation isn't idempotent, we don't just retry on `SysUnknown`.
/// Rather, we leave it up to the caller to handle.
async fn bounded_wait_install_single_chunk<P>(
    target_id: CanisterId,
    wasm_bytes: &[u8],
    arg: &[u8],
    stop_trying: &mut P,
) -> Result<(), RetryError>
where
    P: FnMut() -> bool,
{
    let install_args = InstallCodeArgs {
        mode: CanisterInstallMode::Upgrade(None),
        canister_id: target_id,
        wasm_module: wasm_bytes.to_vec(),
        arg: arg.to_vec(),
    };

    Ok(call_nonidempotent_method_with_retry(
        Call::bounded_wait(Principal::management_canister(), "install_code")
            .with_arg(&install_args),
        stop_trying,
    )
    .await?
    .candid()
    .expect("Candid decoding failed"))
}

/// Upload chunks to a chunk store canister.
pub async fn upload_chunks<P>(
    store_canister_id: CanisterId,
    chunks: Vec<Vec<u8>>,
    stop_trying: &mut P,
) -> Result<(), RetryError>
where
    P: FnMut() -> bool,
{
    let call = Call::bounded_wait(Principal::management_canister(), "clear_chunk_store").with_arg(
        &ClearChunkStoreArgs {
            canister_id: store_canister_id,
        },
    );

    let _: () = call_idempotent_method_with_retry(call, stop_trying)
        .await?
        .candid()
        .expect("Couldnt decode the response from clear_chunk_store");

    for chunk in chunks {
        let chunk_install_args = UploadChunkArgs {
            canister_id: store_canister_id,
            chunk,
        };

        let call = Call::bounded_wait(Principal::management_canister(), "upload_chunk")
            .with_arg(&chunk_install_args);
        let _: UploadChunkResult = call_idempotent_method_with_retry(call, stop_trying)
            .await?
            .candid()
            .expect("Couldn't decode response from upload_chunk");
    }
    Ok(())
}

/// Install a large (>2MB) WASM by referencing pre-uploaded chunks, via `install_chunked_code`.
/// Chunks are assumed to already have been uploaded
async fn bounded_wait_install_chunked<P>(
    target_id: CanisterId,
    chunked: &ChunkedModule,
    arg: &[u8],
    stop_trying: &mut P,
) -> Result<(), RetryError>
where
    P: FnMut() -> bool,
{
    let install_args = InstallChunkedCodeArgs {
        mode: CanisterInstallMode::Upgrade(None),
        target_canister: target_id,
        store_canister: Some(chunked.store_canister_id),
        chunk_hashes_list: chunked
            .chunk_hashes_list
            .iter()
            .map(|hash| ChunkHash { hash: hash.clone() })
            .collect(),
        wasm_module_hash: chunked.wasm_module_hash.clone(),
        arg: arg.to_vec(),
        sender_canister_version: None,
    };

    let install_call = Call::bounded_wait(Principal::management_canister(), "install_chunked_code")
        .with_arg(&install_args);
    let res: () = call_nonidempotent_method_with_retry(install_call, stop_trying).await?.candid().expect("Couldn't decode response from install_chunked_code");
    Ok(res)
}
