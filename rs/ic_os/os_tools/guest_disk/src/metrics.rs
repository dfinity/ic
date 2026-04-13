use crate::crypt::LuksParameters;
use anyhow::{Context, Result};
use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use std::path::Path;

pub fn export_luks_parameters(
    metrics_file: &Path,
    device_path: &Path,
    params: &LuksParameters,
) -> Result<()> {
    let registry = Registry::new();
    let dev_path_str = device_path.to_string_lossy();

    let opts = Opts::new(
        "guest_disk_encryption_info",
        "Information about guest disk encryption configuration",
    );
    let info_gauge = GaugeVec::new(
        opts,
        &[
            "device_path",
            "format",
            "cipher",
            "volume_key_size",
            "keyslot_pbkdf_type",
            "keyslot_pbkdf_iterations",
            "keyslot_cipher",
            "keyslot_key_size",
            "num_keyslots",
            "passes_verification",
        ],
    )
    .context("Failed to create encryption info gauge")?;

    info_gauge
        .with_label_values(&[
            dev_path_str.as_ref(),
            &params.format,
            &format!("{}-{}", params.cipher, params.cipher_mode),
            &params.volume_key_size.to_string(),
            &params.keyslot_pbkdf_type,
            &params.keyslot_pbkdf_iterations.to_string(),
            &params.keyslot_cipher,
            &params.keyslot_key_size.to_string(),
            &params.num_keyslots.to_string(),
            &params.passes_verification.to_string(),
        ])
        .set(1.0);

    registry
        .register(Box::new(info_gauge))
        .context("Failed to register metric")?;

    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    encoder
        .encode(&registry.gather(), &mut buffer)
        .context("Failed to encode metrics")?;

    std::fs::write(metrics_file, buffer)
        .with_context(|| format!("Failed to write metrics to {:?}", metrics_file))?;

    Ok(())
}
