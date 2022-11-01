pub fn encode_metrics(
    metrics: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
) -> std::io::Result<()> {
    metrics.encode_gauge(
        "ckbtc_minter_stable_memory_bytes",
        ic_cdk::api::stable::stable_size() as f64,
        "Size of the stable memory allocated by this canister.",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_cycle_balance",
        ic_cdk::api::canister_balance128() as f64,
        "Cycle balance on this canister.",
    )?;
    Ok(())
}
