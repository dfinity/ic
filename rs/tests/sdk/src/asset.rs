use backoff::{ExponentialBackoff, retry_notify};
use candid::Principal;
use ic_system_test_driver::driver::{ic_gateway_vm::HasIcGatewayVm, test_env::TestEnv};
use slog::{error, info};
use std::time::Duration;

pub fn get_asset_as_string(
    env: &TestEnv,
    ic_gateway_vm_name: &str,
    canister_id: &Principal,
    key: &str,
) -> String {
    let log = env.logger();
    info!(
        log,
        "GET asset {key} as string from canister {canister_id} through ic-gateway {ic_gateway_vm_name}"
    );
    let ic_gateway = env.get_deployed_ic_gateway(ic_gateway_vm_name).unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();
    let ic_gateway_domain = ic_gateway_url.domain().unwrap();
    let asset_url = format!("https://{canister_id}.{ic_gateway_domain}{key}");
    info!(log, "asset url is {asset_url}");

    let backoff = ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(120)),
        ..Default::default()
    };

    let notify = |err, dur| {
        error!(log, "error: {err}");
        error!(log, "retry in {dur:?}");
    };

    let operation = || {
        let client = reqwest::blocking::Client::new();
        let response = client.get(asset_url.clone()).send()?;
        let body = response.text()?;
        Ok(body)
    };

    let body = retry_notify(backoff, operation, notify).unwrap();

    info!(log, "response body: {body}");
    body
}
