use super::*;
use crate::are_bless_alternative_guest_os_version_proposals_enabled;
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;

impl BlessAlternativeGuestOsVersion {
    /// Verifies the following:
    ///
    /// 1. chip_ids
    ///    a. Nonempty.
    ///    b. Each element is itself of length 64.
    ///
    /// 2. rootfs_hash - Contains only hexidecimal characters, i.e. 0-9, A-F
    ///    (lower case is also allowed). Currently, this is a SHA-256 hash,
    ///    which are 32 bytes in length, so this would be 64 characters long,
    ///    but this is not required, nor is it enforced. In terms of length, it
    ///    is only required and enforced that this is nonempty.
    ///
    /// 3. base_guest_launch_measurements
    ///    a. Nonempty.
    ///    b. Each element is valid per GuestLaunchMeasurement (singular).
    pub(crate) fn validate(&self) -> Result<(), GovernanceError> {
        if !are_bless_alternative_guest_os_version_proposals_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "BlessAlternativeGuestOsVersion proposals are not enabled yet.".to_string(),
            ));
        }

        let mut defects = Vec::new();

        defects.extend(validate_chip_ids(&self.chip_ids));
        defects.extend(validate_rootfs_hash(&self.rootfs_hash));
        defects.extend(validate_base_guest_launch_measurements(
            &self.base_guest_launch_measurements,
        ));

        if defects.is_empty() {
            Ok(())
        } else {
            Err(invalid_proposal_error(&defects.join("; ")))
        }
    }

    pub(crate) fn execute(&self) -> Result<(), GovernanceError> {
        if !are_bless_alternative_guest_os_version_proposals_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "BlessAlternativeGuestOsVersion proposals are not enabled yet.".to_string(),
            ));
        }

        // Like with Motion proposals, the execution of these proposals is
        // trivial. The reason for trivial execution in this case is that the
        // way this is actually effected is by a node operator manually running
        // some command(s) on a node in case the normal means of changing
        // software fail (i.e. via a DeployGuestosToAllSubnetNodes proposal).
        // Such manual intervention includes downloading this ProposalInfo, and
        // proceeding with guest boot, once it sees that approved software and
        // configuration (consisting of firmware, kernel, initrd, and kernel
        // command line) is being run. The job of the Governance canister in
        // this case is merely to record whether neurons have (collectively)
        // approved that new software is allowed. Beyond that, making those
        // changes actually take effect is beyond the scope of the Governance
        // canister itself.
        Ok(())
    }
}

/// Validates chip_ids field.
///
/// Returns a list of defects (empty if valid):
/// - chip_ids must be non-empty
/// - Each chip_id must be exactly 64 bytes
fn validate_chip_ids(chip_ids: &[Vec<u8>]) -> Vec<String> {
    let mut defects = Vec::new();

    // Must be nonempty.
    if chip_ids.is_empty() {
        defects.push("chip_ids must not be empty".to_string());
        return defects;
    }

    // Each element must be of length 64.
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

/// Validates rootfs_hash field.
///
/// Returns a list of defects (empty if valid):
/// - Must not be empty
/// - Must contain only hexadecimal characters (0-9, A-F, a-f)
fn validate_rootfs_hash(hexidecimal_fingerprint: &str) -> Vec<String> {
    let mut defects = Vec::new();

    // Must not be empty.
    if hexidecimal_fingerprint.is_empty() {
        defects.push("rootfs_hash must not be empty".to_string());
    }

    // Must consist of only hexidecimal characters.
    if !hexidecimal_fingerprint
        .chars()
        .all(|c| c.is_ascii_hexdigit())
    {
        defects.push(format!(
            "rootfs_hash must contain only hexadecimal characters \
             (0-9, A-F, a-f), got: {}",
            hexidecimal_fingerprint,
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
    let Some(measurements) = measurements else {
        defects.push("base_guest_launch_measurements must be present".to_string());
        return defects;
    };

    // Some must wrap a valid GuestLaunchMeasurements.
    if let Err(validation_defects) = measurements.validate() {
        defects.extend(validation_defects);
    }

    defects
}

#[cfg(test)]
#[path = "bless_alternative_guest_os_version_tests.rs"]
mod tests;
