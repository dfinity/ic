use candid::candid_method;
use ic_cdk_macros::{init, update};
use rate_limits_api::{GetConfigResponse, InitArg, Version};
use storage::{get_stable_version, set_stable_version};
use types::{ConfigResponse, OutputConfig};
mod storage;
mod types;

#[init]
#[candid_method(init)]
fn init(_init_arg: InitArg) {
    // Initialize version to 1
    set_stable_version(1);
    // TODO: init periodic timer for fetching API BNs principals.
}

#[update(name = "get_config")]
#[candid_method(update, rename = "get_config")]
fn get_config(_version: Option<Version>) -> GetConfigResponse {
    let version = get_stable_version();

    let response = ConfigResponse {
        version,
        active_since: 1,
        config: OutputConfig { rules: vec![] },
    };

    Ok(response.into())
}
