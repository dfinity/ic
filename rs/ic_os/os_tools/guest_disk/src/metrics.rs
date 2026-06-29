use crate::crypt::{LuksParameters, verify_luks_parameters};
use anyhow::{Context, Result};
use libcryptsetup_rs::consts::vals::KeyslotInfo;
use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use std::path::Path;
use tracing::warn;

pub(crate) fn export_luks_parameters(
    registry: &Registry,
    luks_parameters: &LuksParameters,
    device_path: &Path,
    active_keyslot: u32,
) -> Result<()> {
    let labels = build_luks_metric_labels(luks_parameters, device_path, active_keyslot)?;
    let label_names = labels.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    let label_values = labels
        .iter()
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();

    let opts = Opts::new(
        "guest_disk_encryption_info",
        "Information about guest disk encryption configuration",
    );
    let info_gauge =
        GaugeVec::new(opts, &label_names).context("Failed to create encryption info gauge")?;

    info_gauge.with_label_values(&label_values).set(1.0);

    registry
        .register(Box::new(info_gauge))
        .context("Failed to register metric")?;

    Ok(())
}

fn build_luks_metric_labels(
    luks_parameters: &LuksParameters,
    device_path: &Path,
    active_keyslot: u32,
) -> Result<Vec<(&'static str, String)>> {
    let active_keyslot_parameters = luks_parameters
        .keyslots
        .iter()
        .find(|keyslot| keyslot.slot == active_keyslot)
        .with_context(|| format!("Active keyslot {active_keyslot} not found"))?;
    let keyslot_pbkdf_type = active_keyslot_parameters
        .pbkdf_type
        .as_ref()
        .with_context(|| format!("Missing PBKDF type for keyslot {active_keyslot}"))?;
    let keyslot_pbkdf_iterations = active_keyslot_parameters
        .pbkdf_iterations
        .with_context(|| format!("Missing PBKDF iterations for keyslot {active_keyslot}"))?;
    let keyslot_cipher = active_keyslot_parameters
        .cipher
        .as_ref()
        .with_context(|| format!("Missing cipher for keyslot {active_keyslot}"))?;
    let keyslot_key_size = active_keyslot_parameters
        .key_size
        .with_context(|| format!("Missing key size for keyslot {active_keyslot}"))?;
    let num_keyslots = luks_parameters
        .keyslots
        .iter()
        .filter(|keyslot| {
            matches!(
                keyslot.status,
                KeyslotInfo::Active | KeyslotInfo::ActiveLast
            )
        })
        .count();
    let passes_verification = verify_luks_parameters(luks_parameters).is_ok();

    Ok(vec![
        ("device_path", device_path.to_string_lossy().to_string()),
        ("format", format!("{:?}", luks_parameters.format)),
        (
            "cipher",
            format!("{}-{}", luks_parameters.cipher, luks_parameters.cipher_mode),
        ),
        (
            "volume_key_size",
            luks_parameters.volume_key_size.to_string(),
        ),
        ("keyslot_pbkdf_type", format!("{:?}", keyslot_pbkdf_type)),
        (
            "keyslot_pbkdf_iterations",
            keyslot_pbkdf_iterations.to_string(),
        ),
        ("keyslot_cipher", keyslot_cipher.clone()),
        ("keyslot_key_size", keyslot_key_size.to_string()),
        ("num_keyslots", num_keyslots.to_string()),
        ("passes_verification", passes_verification.to_string()),
    ])
}

/// Registers the status of the attached LUKS2 header on the Store data device with the given
/// registry. Call [`write_metrics`] at the end of the program to persist all registered metrics to
/// disk.
pub(crate) fn export_attached_luks2_header_status(
    registry: &Registry,
    device_path: &Path,
    attached_header_present: Result<bool>,
) -> Result<()> {
    let opts = Opts::new(
        "guest_disk_store_attached_luks2_header_status",
        "Status of the attached (on-device) LUKS2 header on the Store partition data device",
    );
    let header_status = GaugeVec::new(opts, &["device_path", "status"])
        .context("Failed to create attached LUKS2 header status gauge")?;

    let device_path_str = device_path.to_string_lossy();
    let status_str = match attached_header_present {
        Ok(true) => "present",
        Ok(false) => "absent",
        Err(_) => "error",
    };
    let label_values: Vec<&str> = vec![&device_path_str, status_str];

    header_status
        .with_label_values(&label_values)
        .set(1.0);

    registry
        .register(Box::new(header_status))
        .context("Failed to register attached LUKS2 header status metric")?;

    Ok(())
}

/// Encodes all metrics registered in `registry` and writes them to `metrics_file`.
pub fn write_metrics(registry: &Registry, metrics_file: &Path) {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    if let Err(e) = encoder.encode(&registry.gather(), &mut buffer) {
        warn!("Failed to encode metrics: {e:#}");
        return;
    }
    if let Err(e) = std::fs::write(metrics_file, buffer) {
        warn!(
            "Failed to write metrics to {}: {e:#}",
            metrics_file.display()
        );
    }
}
