use super::*;

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
        todo!() // DO NOT MERGE
    }
}
