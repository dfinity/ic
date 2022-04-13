//! Module for managing the canisters in test.

use ic_canister_client::{Agent, HttpClient, Sender as AgentSender};
use ic_ic00_types::CanisterInstallMode;
use ic_types::{
    ic00::{
        CanisterIdRecord, InstallCodeArgs, Payload, ProvisionalCreateCanisterWithCyclesArgs, IC_00,
    },
    CanisterId,
};
use std::{fs::File, io::Read, path::Path, time::Duration};
use url::Url;

const REQUESTED_MEMORY_ALLOCATION: Option<u64> = None; // Best effort memory allocation
const COUNTER_CANISTER_WAT: &[u8] = include_bytes!("counter.wat");
/// Creates/installs the canister across the given replicas
pub(crate) async fn setup_canister(
    http_client: HttpClient,
    agent_sender: AgentSender,
    urls: &[String],
    wasm_file_path: Option<&Path>,
) -> Result<CanisterId, String> {
    let mut canister_id = None;
    for url in urls {
        match create_canister(http_client.clone(), agent_sender.clone(), url).await {
            Ok(id) => {
                canister_id = Some(id);
                break;
            }
            Err(err) => println!(
                "⚠️  Could not create a canister at replica url {}. {}",
                url, err
            ),
        }
    }
    let canister_id = canister_id.ok_or_else(|| {
        "💣  Failed to create a canister on all provided replica nodes".to_string()
    })?;

    for url in urls {
        match install_canister(
            http_client.clone(),
            agent_sender.clone(),
            url,
            canister_id,
            wasm_file_path,
        )
        .await
        {
            Ok(_) => return Ok(canister_id),
            Err(err) => println!(
                "⚠️  Could not install a canister at replica url {}. {}",
                url, err
            ),
        }
    }
    Err("💣  Failed to install canister. Did you provide replica nodes URLs?".to_string())
}

/// Creates a canister.
pub(crate) async fn create_canister(
    http_client: HttpClient,
    agent_sender: AgentSender,
    url: &str,
) -> Result<CanisterId, String> {
    // Two requests created separately are never identical, even without a
    // nonce, due to the presence of expiry_time. Therefore this function
    // will create a NEW canister id every time it is invoked.
    let agent = Agent::new_with_client(http_client, Url::parse(url).unwrap(), agent_sender)
        .with_ingress_timeout(Duration::from_secs(5 * 60));

    debug!("Create canister with agent: {:?}", agent);
    let creation_result = agent
        .execute_update(
            &IC_00,
            ic_types::ic00::Method::ProvisionalCreateCanisterWithCycles,
            ProvisionalCreateCanisterWithCyclesArgs::new(Some(u64::MAX as u128)).encode(),
            vec![],
        )
        .await?;

    match creation_result {
        None => Err(
            "A call to create a canister returned without a canister id in the reply".to_string(),
        ),
        Some(bytes) => match CanisterIdRecord::decode(bytes.as_slice()) {
            Ok(id) => {
                let canister_id = id.get_canister_id();
                println!(
                    "📦 Successfully created canister at URL {}. ID: {} (use with --canister-id)",
                    url,
                    console::style(&canister_id).bold()
                );
                Ok(canister_id)
            }
            Err(e) => Err(format!(
                "Could not decode the canister id returned by a call to create a canister: {}",
                e
            )),
        },
    }
}

/// Installs a canister.
pub(crate) async fn install_canister(
    http_client: HttpClient,
    agent_sender: AgentSender,
    url: &str,
    canister_id: CanisterId,
    wasm_file_path: Option<&Path>,
) -> Result<(), String> {
    let agent = Agent::new_with_client(http_client, Url::parse(url).unwrap(), agent_sender)
        .with_ingress_timeout(Duration::from_secs(5 * 60));

    let bytes = if let Some(wasm_file_path) = wasm_file_path {
        // Buffer to store bytes of the canister code
        let mut bytes_buffer = Vec::new();
        let mut f = File::open(&wasm_file_path).map_err(|err| {
            format!(
                "Failed to open canister file: {:?} - try running from the rs directory. {}",
                wasm_file_path, err
            )
        })?;

        f.read_to_end(&mut bytes_buffer).map_err(|err| {
            format!(
                "Could not read canister file {:?} contents: {}",
                wasm_file_path, err
            )
        })?;

        if wasm_file_path.extension() == Some(std::ffi::OsStr::new("wat")) {
            wabt::wat2wasm(bytes_buffer).unwrap()
        } else {
            bytes_buffer
        }
    } else {
        wabt::wat2wasm(COUNTER_CANISTER_WAT).unwrap()
    };

    let install_args = InstallCodeArgs::new(
        CanisterInstallMode::Reinstall,
        canister_id,
        bytes,
        vec![],
        None,
        REQUESTED_MEMORY_ALLOCATION,
        None,
    );

    agent.install_canister(install_args).await?;
    println!("📦 Successfully installed canister code at URL {}.", url);
    Ok(())
}
