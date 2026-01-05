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
        let Self {
            guest_launch_measurements,
        } = self;

        let mut defects = Vec::new();

        // Not vec[].
        if guest_launch_measurements.is_empty() {
            defects.push("guest_launch_measurements must not be empty".to_string());
            return Err(defects);
        }

        // Each element is valid.
        for (i, measurement) in guest_launch_measurements.iter().enumerate() {
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
    /// - metadata need not be present, but if it is, it must be valid.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let Self {
            measurement,
            metadata,
        } = self;

        let mut defects = Vec::new();

        // Measurement must be 48 bytes, per SEV-SNP.
        if measurement.len() != SEV_SNP_MEASUREMENT_LENGTH {
            defects.push(format!(
                "measurement must be exactly {} bytes (SEV-SNP measurement), got {} bytes",
                SEV_SNP_MEASUREMENT_LENGTH,
                measurement.len()
            ));
        }

        // Metadata can be absent, but if it is present, it must (of course) be valid.
        if let Some(metadata) = metadata.as_ref() {
            match metadata.validate() {
                Ok(()) => (),
                Err(metadata_defects) => defects.extend(metadata_defects),
            }
        }

        if defects.is_empty() {
            Ok(())
        } else {
            Err(defects)
        }
    }
}

impl v1::GuestLaunchMeasurementMetadata {
    const MAX_KERNEL_CMDLINE_LEN: usize = 100 * 1024;

    /// Returns a list of defects (or Ok):
    ///
    /// - kernel_cmdline can any value, including None, and Some(""). The only
    ///   restriction is that it must not exceed 100 KiB.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let Self { kernel_cmdline } = self;

        let mut defects = vec![];

        // kernel_cmdline must not be too long.
        let len = kernel_cmdline
            .as_ref()
            .map(|kernel_cmdline| kernel_cmdline.len())
            .unwrap_or(0);
        if len > Self::MAX_KERNEL_CMDLINE_LEN {
            defects.push(format!(
                "kernel_cmdline is too long. Was {} KiB, but it is allowed to be at most {} KiB.",
                len as f64 / 1024.0,
                Self::MAX_KERNEL_CMDLINE_LEN as f64 / 1024.0,
            ))
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
