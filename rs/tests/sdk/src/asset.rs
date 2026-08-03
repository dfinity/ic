use backon::{BlockingRetryable, ExponentialBuilder};
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

    // On the Local backend the gateway domain (and its per-canister subdomains)
    // is not resolvable via DNS and is served with a self-signed certificate, so
    // resolve the requested host directly to the gateway VM and accept the
    // self-signed cert.
    let parsed_asset_url = reqwest::Url::parse(&asset_url).unwrap();
    let resolve_override = ic_gateway.resolve_override_for_url(&parsed_asset_url);
    let accept_invalid_certs = ic_gateway.uses_self_signed_cert();

    let backoff = ExponentialBuilder::new()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(60))
        .with_factor(1.5)
        .with_jitter()
        .with_total_delay(Some(Duration::from_secs(120)))
        .without_max_times();

    let notify = |err: &reqwest::Error, dur: Duration| {
        error!(log, "error: {err}");
        error!(log, "retry in {dur:?}");
    };

    let operation = || {
        let mut builder = reqwest::blocking::Client::builder();
        if let Some((domain, addr)) = &resolve_override {
            builder = builder.resolve(domain, *addr);
        }
        let client = builder
            .danger_accept_invalid_certs(accept_invalid_certs)
            .build()?;
        let response = client.get(asset_url.clone()).send()?;
        let body = response.text()?;
        Ok(body)
    };

    let body = operation.retry(backoff).notify(notify).call().unwrap();

    info!(log, "response body: {body}");
    body
}
