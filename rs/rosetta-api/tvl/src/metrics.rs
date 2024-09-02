pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    const WASM_PAGE_SIZE_IN_BYTES: f64 = 65536.0;

    w.encode_gauge(
        "tvl_stable_memory_pages",
        ic_cdk::api::stable::stable64_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "tvl_stable_memory_bytes",
        ic_cdk::api::stable::stable64_size() as f64 * WASM_PAGE_SIZE_IN_BYTES,
        "Size of the stable memory allocated by this canister.",
    )?;
    w.encode_gauge(
        "tvl_cycle_balance",
        ic_cdk::api::canister_balance128() as f64,
        "Cycle balance on this canister.",
    )?;
    Ok(())
}
