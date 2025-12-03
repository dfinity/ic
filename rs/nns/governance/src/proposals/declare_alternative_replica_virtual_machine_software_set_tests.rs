use super::*;
use crate::{
    pb::v1::{GuestLaunchMeasurement, GuestLaunchMeasurementMetadata, GuestLaunchMeasurements},
    temporarily_disable_declare_alternative_replica_virtual_machine_software_set_proposals,
    temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals,
};
use ic_nervous_system_common_test_utils::assert_contains_all_key_words;

#[test]
fn test_validate_chip_ids_empty() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let defects = validate_chip_ids(&[]);
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["chip_ids", "empty"]);
}

#[test]
fn test_validate_chip_ids_valid() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let chip_ids = vec![vec![0u8; 64], vec![1u8; 64]];
    let defects = validate_chip_ids(&chip_ids);
    assert!(defects.is_empty(), "{defects:#?}");
}

#[test]
fn test_validate_chip_ids_wrong_length() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let chip_ids = vec![
        vec![0u8; 64],  // Valid
        vec![0u8; 32],  // Too short
        vec![0u8; 128], // Too long
    ];
    let defects = validate_chip_ids(&chip_ids);
    assert_eq!(defects.len(), 2, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["chip_ids[1]", "32"]);
    assert_contains_all_key_words(&defects[1], &["chip_ids[2]", "128"]);
}

#[test]
fn test_validate_hexadecimal_recovery_rootfs_fingerprint_valid() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let defects = validate_hexadecimal_recovery_rootfs_fingerprint("0123456789abcdefABCDEF");
    assert!(defects.is_empty(), "{defects:#?}");
}

#[test]
fn test_validate_hexadecimal_recovery_rootfs_fingerprint_invalid() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let defects = validate_hexadecimal_recovery_rootfs_fingerprint("not-hex!");
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["hexadecimal", "not-hex!"]);
}

#[test]
fn test_validate_hexadecimal_recovery_rootfs_fingerprint_empty_is_invalid() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    // Empty fingerprint should be rejected
    let defects = validate_hexadecimal_recovery_rootfs_fingerprint("");
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["empty"]);
}

#[test]
fn test_validate_base_guest_launch_measurements_none() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let defects = validate_base_guest_launch_measurements(&None);
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["base_guest_launch_measurements", "present"]);
}

#[test]
fn test_validate_base_guest_launch_measurements_empty() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![],
    };
    let defects = validate_base_guest_launch_measurements(&Some(measurements));
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["base_guest_launch_measurements", "empty"]);
}

#[test]
fn test_validate_base_guest_launch_measurements_valid() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let guest_launch_measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![GuestLaunchMeasurement {
            measurement: vec![0u8; 48],
            metadata: Some(GuestLaunchMeasurementMetadata {
                kernel_cmdline: "console=ttyS0".to_string(),
            }),
        }],
    };
    let defects = validate_base_guest_launch_measurements(&Some(guest_launch_measurements));
    assert!(defects.is_empty(), "{defects:#?}");
}

#[test]
fn test_validate_base_guest_launch_measurements_multiple_defects() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![
            // Valid measurement
            GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "console=ttyS0".to_string(),
                }),
            },
            // Wrong measurement size
            GuestLaunchMeasurement {
                measurement: vec![0u8; 32],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "console=ttyS0".to_string(),
                }),
            },
            // Missing metadata
            GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: None,
            },
            // Empty kernel_cmdline
            GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "".to_string(),
                }),
            },
        ],
    };

    let defects = validate_base_guest_launch_measurements(&Some(measurements));

    assert_eq!(defects.len(), 3, "{defects:#?}");

    assert_contains_all_key_words(&defects[0], &["guest_launch_measurements[1]", "48", "32"]);
    assert_contains_all_key_words(
        &defects[1],
        &["guest_launch_measurements[2]", "metadata", "present"],
    );
    assert_contains_all_key_words(
        &defects[2],
        &["guest_launch_measurements[3]", "kernel_cmdline", "empty"],
    );
}

#[test]
fn test_validate_guest_launch_measurement_valid() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 48],
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: "console=ttyS0".to_string(),
        }),
    };
    let defects = validate_guest_launch_measurement(&measurement);
    assert!(defects.is_empty(), "{defects:#?}");
}

#[test]
fn test_validate_guest_launch_measurement_wrong_size() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 32],
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: "console=ttyS0".to_string(),
        }),
    };
    let defects = validate_guest_launch_measurement(&measurement);
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["48", "32"]);
}

#[test]
fn test_validate_guest_launch_measurement_no_metadata() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 48],
        metadata: None,
    };
    let defects = validate_guest_launch_measurement(&measurement);
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["metadata", "present"]);
}

#[test]
fn test_validate_guest_launch_measurement_empty_kernel_cmdline() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 48],
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: "".to_string(),
        }),
    };

    let defects = validate_guest_launch_measurement(&measurement);

    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["kernel", "empty"]);
}

#[test]
fn test_validate_guest_launch_measurement_multiple_defects() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 32], // Wrong size
        metadata: None,             // Missing metadata
    };
    let defects = validate_guest_launch_measurement(&measurement);
    // Should report measurement size error, then early return on missing metadata
    assert_eq!(defects.len(), 2, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["48"]);
    assert_contains_all_key_words(&defects[1], &["metadata", "present"]);
}

#[test]
fn test_declare_alternative_replica_virtual_machine_software_set_validate_valid() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let proposal = DeclareAlternativeReplicaVirtualMachineSoftwareSet {
        chip_ids: vec![vec![0u8; 64]],
        hexidecimal_recovery_rootfs_fingerprint: "abc123".to_string(),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: vec![GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "console=ttyS0".to_string(),
                }),
            }],
        }),
    };

    assert_eq!(proposal.validate(), Ok(()));
}

#[test]
fn test_declare_alternative_replica_virtual_machine_software_set_validate_multiple_errors() {
    let _guard =
        temporarily_enable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let proposal = DeclareAlternativeReplicaVirtualMachineSoftwareSet {
        chip_ids: vec![],                                                // Empty
        hexidecimal_recovery_rootfs_fingerprint: "not-hex!".to_string(), // Invalid
        base_guest_launch_measurements: None,                            // Missing
    };

    let result = proposal.validate().unwrap_err();

    assert_eq!(
        ErrorType::try_from(result.error_type),
        Ok(ErrorType::InvalidProposal),
        "{result:?}"
    );
    assert_contains_all_key_words(
        &result.error_message,
        &[
            "chip_ids",
            "empty",
            "hexidecimal",
            "base_guest_launch_measurements",
            "present",
        ],
    );
}

#[test]
fn test_declare_alternative_replica_virtual_machine_software_set_disabled() {
    // Explicitly disable the flag - test that proposals are rejected when disabled
    let _guard =
        temporarily_disable_declare_alternative_replica_virtual_machine_software_set_proposals();

    let proposal = DeclareAlternativeReplicaVirtualMachineSoftwareSet {
        chip_ids: vec![vec![0u8; 64]],
        hexidecimal_recovery_rootfs_fingerprint: "abc123".to_string(),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: vec![GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "console=ttyS0".to_string(),
                }),
            }],
        }),
    };

    let result = proposal.validate().unwrap_err();
    assert_eq!(
        ErrorType::try_from(result.error_type),
        Ok(ErrorType::InvalidProposal),
        "{result:?}"
    );
    assert_contains_all_key_words(
        &result.error_message,
        &[
            "DeclareAlternativeReplicaVirtualMachineSoftwareSet",
            "not enabled",
        ],
    );

    // Also test execute() is blocked
    let result = proposal.execute().unwrap_err();
    assert_eq!(
        ErrorType::try_from(result.error_type),
        Ok(ErrorType::InvalidProposal),
        "{result:?}"
    );
    assert_contains_all_key_words(
        &result.error_message,
        &[
            "DeclareAlternativeReplicaVirtualMachineSoftwareSet",
            "not enabled",
        ],
    );
}
