use crate::crypt::verify_luks_parameters;
use anyhow::{Context, Result};
use libcryptsetup_rs::CryptDevice;
use libcryptsetup_rs::consts::vals::KeyslotInfo;
use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use std::path::Path;

pub fn export_luks_parameters(
    metrics_file: &Path,
    crypt_device: &mut CryptDevice,
    device_path: &Path,
    active_keyslot: u32,
) -> Result<()> {
    let registry = Registry::new();
    let labels = build_luks_metric_labels(crypt_device, device_path, active_keyslot)?;
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

    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    encoder
        .encode(&registry.gather(), &mut buffer)
        .context("Failed to encode metrics")?;

    std::fs::write(metrics_file, buffer)
        .with_context(|| format!("Failed to write metrics to {:?}", metrics_file))?;

    Ok(())
}

fn build_luks_metric_labels(
    crypt_device: &mut CryptDevice,
    device_path: &Path,
    active_keyslot: u32,
) -> Result<Vec<(&'static str, String)>> {
    let format = crypt_device
        .format_handle()
        .get_type()
        .context("Failed to get encryption format")?;
    let mut status_handle = crypt_device.status_handle();
    let cipher = status_handle
        .get_cipher()
        .context("Failed to get cipher")?
        .to_string();
    let cipher_mode = status_handle
        .get_cipher_mode()
        .context("Failed to get cipher mode")?
        .to_string();
    let volume_key_size = status_handle.get_volume_key_size() as usize;

    let mut keyslot_handle = crypt_device.keyslot_handle();
    let mut num_keyslots = 0;
    for key_slot in 0..32 {
        let status = keyslot_handle
            .status(key_slot)
            .with_context(|| format!("Failed to get status for keyslot {key_slot}"))?;
        if matches!(status, KeyslotInfo::Active | KeyslotInfo::ActiveLast) {
            num_keyslots += 1;
        }
    }

    let keyslot_pbkdf = keyslot_handle
        .get_pbkdf(active_keyslot)
        .context("Failed to get PBKDF type for active keyslot")?;
    let keyslot_pbkdf_type = format!("{:?}", keyslot_pbkdf.type_);
    let keyslot_pbkdf_iterations = keyslot_pbkdf.iterations.to_string();

    let keyslot_encryption = keyslot_handle
        .get_encryption(Some(active_keyslot))
        .context("Failed to get encryption for active keyslot")?;
    let keyslot_cipher = keyslot_encryption.0.to_string();
    let keyslot_key_size = keyslot_encryption.1.to_string();

    let passes_verification = verify_luks_parameters(crypt_device).is_ok();

    Ok(vec![
        ("device_path", device_path.to_string_lossy().to_string()),
        ("format", format!("{:?}", format)),
        ("cipher", format!("{}-{}", cipher, cipher_mode)),
        ("volume_key_size", volume_key_size.to_string()),
        ("keyslot_pbkdf_type", keyslot_pbkdf_type),
        ("keyslot_pbkdf_iterations", keyslot_pbkdf_iterations),
        ("keyslot_cipher", keyslot_cipher),
        ("keyslot_key_size", keyslot_key_size),
        ("num_keyslots", num_keyslots.to_string()),
        ("passes_verification", passes_verification.to_string()),
    ])
}
