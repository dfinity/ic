use super::*;
use crate::pb::v1::GuestLaunchMeasurements;

/// Length of SEV-SNP launch measurements in bytes.
///
/// SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) is an AMD
/// technology that that protects a virtual machine's memory from being read
/// and/or modified by the host.
///
/// A "launch measurement" is a cryptographic hash (48 bytes) of the software
/// that was used to launch a VM, which consists of the following pieces:
///
///     1. firmware
///     2. kernel
///     3. initrd
///     4. kernel command line
///
/// A launch measurement is part of a signed artifact called an "attestation". A
/// remote machine can use an attestation to securely verify that the VM is
/// running what it's supposed to.
///
/// For more details, see:
/// - AMD SEV-SNP specification: https://www.amd.com/en/developer/sev.html
/// - Launch measurement details: Section 8.17.3 of the SEV-SNP API specification
const SEV_SNP_MEASUREMENT_LENGTH: usize = 48;

impl DeclareAlternativeReplicaVirtualMachineSoftwareSet {
    /// Verifies the following:
    ///
    /// 1. chip_ids
    ///    a. Nonempty.
    ///    b. Each element is itself of length 64.
    ///
    /// 2. hexidecimal_recovery_rootfs_fingerprint - Contains only hexidecimal
    ///    characters, i.e. 0-9, A-F (lower case is also allowed). Presumably,
    ///    this would contain a SHA-256 hash, which are 32 bytes in length, so
    ///    this would be 64 characters long, but this is not required, nor is it
    ///    enforced.
    ///
    /// 3. base_guest_launch_measurements
    ///    a. Noneempty.
    ///    b. Each element is valid per GuestLaunchMeasurement (singular).
    pub(crate) fn validate(&self) -> Result<(), GovernanceError> {
        let mut defects = Vec::new();

        defects.extend(validate_chip_ids(&self.chip_ids));
        defects.extend(validate_hexadecimal_recovery_rootfs_fingerprint(
            &self.hexidecimal_recovery_rootfs_fingerprint,
        ));
        defects.extend(validate_base_guest_launch_measurements(
            &self.base_guest_launch_measurements,
        ));

        if defects.is_empty() {
            Ok(())
        } else {
            Err(invalid_proposal_error(&defects.join("; ")))
        }
    }
}

/// Validates chip_ids field.
///
/// Returns a list of defects (empty if valid):
/// - chip_ids must be non-empty
/// - Each chip_id must be exactly 64 bytes
fn validate_chip_ids(chip_ids: &[Vec<u8>]) -> Vec<String> {
    let mut defects = Vec::new();

    if chip_ids.is_empty() {
        defects.push("chip_ids must not be empty".to_string());
        return defects;
    }

    for (i, chip_id) in chip_ids.iter().enumerate() {
        if chip_id.len() != 64 {
            defects.push(format!(
                "chip_ids[{}] must be exactly 64 bytes, got {} bytes",
                i,
                chip_id.len()
            ));
        }
    }

    defects
}

/// Validates hexidecimal_recovery_rootfs_fingerprint field.
///
/// Returns a list of defects (empty if valid):
/// - Must not be empty
/// - Must contain only hexadecimal characters (0-9, A-F, a-f)
fn validate_hexadecimal_recovery_rootfs_fingerprint(hexidecimal_fingerprint: &str) -> Vec<String> {
    let mut defects = Vec::new();

    // Must not be empty.
    if hexidecimal_fingerprint.is_empty() {
        defects.push("hexidecimal_recovery_rootfs_fingerprint must not be empty".to_string());
    }

    // Must consist of only hexidecimal characters.
    if !hexidecimal_fingerprint
        .chars()
        .all(|c| c.is_ascii_hexdigit())
    {
        defects.push(format!(
            "hexidecimal_recovery_rootfs_fingerprint must contain only \
             hexadecimal characters (0-9, A-F, a-f), got: {}",
            String::from_utf8_lossy(hexidecimal_fingerprint.as_bytes())
        ));
    }

    defects
}

/// Validates base_guest_launch_measurements field.
///
/// Returns a list of defects (empty if valid):
/// - Must be present (not None)
/// - Must be non-empty (at least one measurement)
/// - Each measurement must be valid (48 bytes, non-empty kernel_cmdline)
fn validate_base_guest_launch_measurements(
    measurements: &Option<GuestLaunchMeasurements>,
) -> Vec<String> {
    let mut defects = Vec::new();

    // Not None.
    let measurements = match measurements {
        Some(m) => m,
        None => {
            defects.push("base_guest_launch_measurements must be present".to_string());
            return defects;
        }
    };

    // Not vec[].
    if measurements.guest_launch_measurements.is_empty() {
        defects.push("base_guest_launch_measurements must not be empty".to_string());
        return defects;
    }

    // Each element is valid.
    for (i, measurement) in measurements.guest_launch_measurements.iter().enumerate() {
        defects.extend(
            validate_guest_launch_measurement(measurement)
                .into_iter()
                .map(|defect| format!("guest_launch_measurements[{}]: {}", i, defect)),
        );
    }

    defects
}

/// Validates a single GuestLaunchMeasurement (singular).
///
/// Returns a list of defects (empty if valid):
/// - measurement must be exactly 48 bytes (SEV-SNP measurement size)
/// - metadata must be present
/// - metadata.kernel_cmdline must not be empty
fn validate_guest_launch_measurement(
    measurement: &crate::pb::v1::GuestLaunchMeasurement,
) -> Vec<String> {
    let mut defects = Vec::new();

    // Measurement must be 48 bytes, per SEV-SNP.
    if measurement.measurement.len() != SEV_SNP_MEASUREMENT_LENGTH {
        defects.push(format!(
            "measurement must be exactly {} bytes (SEV-SNP measurement), got {} bytes",
            SEV_SNP_MEASUREMENT_LENGTH,
            measurement.measurement.len()
        ));
    }

    // Require metadata.
    let metadata = match &measurement.metadata {
        Some(ok) => ok,
        None => {
            defects.push("metadata must be present".to_string());
            return defects;
        }
    };
    // Kernel command line must be nonempty.
    if metadata.kernel_cmdline.is_empty() {
        defects.push("metadata.kernel_cmdline must not be empty".to_string());
    }

    defects
}

#[cfg(test)]
#[path = "declare_alternative_replica_virtual_machine_software_set_tests.rs"]
mod tests;
