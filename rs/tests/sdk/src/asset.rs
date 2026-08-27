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

    // On the Local backend the driver cannot resolve the gateway domain (nor its
    // per-canister subdomains), so resolve the requested host directly to the
    // gateway VM, and trust the CA that issued its certificate.
    let parsed_asset_url = reqwest::Url::parse(&asset_url).unwrap();
    let resolve_override = ic_gateway.resolve_override_for_url(&parsed_asset_url);
    let root_cert = ic_gateway.root_certificate().unwrap();

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
        if let Some(cert) = &root_cert {
            builder = builder.add_root_certificate(cert.clone());
        }
        let client = builder.build()?;
        let response = client.get(asset_url.clone()).send()?;
        let body = response.text()?;
        Ok(body)
    };

    let body = operation.retry(backoff).notify(notify).call().unwrap();

    info!(log, "response body: {body}");
    body
}
