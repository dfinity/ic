#[allow(clippy::all)]
#[path = "../gen/registry/registry.replica_version.v1.rs"]
pub mod v1;

/// Length of SEV-SNP launch measurements in bytes.
///
/// SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) is an AMD
/// technology that that protects a virtual machine's memory from being read
/// and/or modified by the host.
///
/// A "launch measurement" is a cryptographic hash (48 bytes) of how the VM was
/// launched. A non-exhaustive list of key ingredients of how a VM is launched
/// (and therefore, affect the measurement) are the following:
///
/// 1. firmware
/// 2. kernel
/// 3. initrd
/// 4. kernel command line
///
/// A launch measurement is part of a signed artifact called an "attestation". A
/// remote machine can use an attestation to securely verify that the VM is
/// running what it's supposed to.
///
/// For more details, see:
///
/// - AMD SEV-SNP specification: https://www.amd.com/en/developer/sev.html
///
/// - In particular, "SEV Secure Nested Paging Firmware ABI Specification" might
///   be of interest:
///   https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf
const SEV_SNP_MEASUREMENT_LENGTH: usize = 48;

impl v1::GuestLaunchMeasurements {
    /// Returns a list of defects (or Ok).
    ///
    /// - Must be non-empty (at least one measurement)
    ///
    /// - Each element in measurements must be valid (see
    ///   GuestLaunchMeasurement::validate).
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut defects = Vec::new();

        // Not vec[].
        if self.guest_launch_measurements.is_empty() {
            defects.push("guest_launch_measurements must not be empty".to_string());
            return Err(defects);
        }

        // Each element is valid.
        for (i, measurement) in self.guest_launch_measurements.iter().enumerate() {
            defects.extend(
                measurement
                    .validate()
                    .err()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|defect| format!("guest_launch_measurements[{}]: {}", i, defect)),
            );
        }

        if defects.is_empty() {
            Ok(())
        } else {
            Err(defects)
        }
    }
}

impl v1::GuestLaunchMeasurement {
    /// Returns a list of defects (or Ok):
    ///
    /// - measurement must be exactly 48 bytes (SEV-SNP measurement size)
    ///
    /// - metadata.kernel_cmdline must not be empty (but metadata need not be
    ///   present).
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut defects = Vec::new();

        // Measurement must be 48 bytes, per SEV-SNP.
        #[allow(deprecated)]
        if self.measurement.len() != SEV_SNP_MEASUREMENT_LENGTH {
            defects.push(format!(
                "measurement must be exactly {} bytes (SEV-SNP measurement), got {} bytes",
                SEV_SNP_MEASUREMENT_LENGTH,
                self.measurement.len()
            ));
        }

        if let Some(encoded_measurement) = &self.encoded_measurement {
            match hex::decode(encoded_measurement) {
                Ok(decoded_measurement) => {
                    if decoded_measurement.len() != SEV_SNP_MEASUREMENT_LENGTH {
                        defects.push(format!(
                        "encoded_measurement must be exactly {} bytes (SEV-SNP measurement), got {} bytes",
                        SEV_SNP_MEASUREMENT_LENGTH,
                        decoded_measurement.len()
                    ));
                    }
                }
                Err(e) => {
                    defects.push(format!("encoded_measurement must be valid hex: '{}'", e));
                }
            }
        }

        // kernel_cmdline must be nonempty, even though metadata is optional.
        let ok = self
            .metadata
            .as_ref()
            // kernel_cmdline must be nonempty.
            .map(|metadata| !metadata.kernel_cmdline.is_empty())
            // Absent metadata is ok though.
            .unwrap_or(true);
        if !ok {
            defects.push("metadata.kernel_cmdline must not be empty".to_string());
        }

        if defects.is_empty() {
            Ok(())
        } else {
            Err(defects)
        }
    }
}

#[cfg(test)]
mod tests;
