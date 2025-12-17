use super::*;
use crate::{
    temporarily_disable_bless_alternative_guest_os_version_proposals,
    temporarily_enable_bless_alternative_guest_os_version_proposals,
};
use ic_nervous_system_common_test_utils::assert_contains_all_key_words;
use ic_protobuf::registry::replica_version::v1::{
    GuestLaunchMeasurement, GuestLaunchMeasurementMetadata, GuestLaunchMeasurements,
};

#[test]
fn test_validate_chip_ids_empty() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let defects = validate_chip_ids(&[]);
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["chip_ids", "empty"]);
}

#[test]
fn test_validate_chip_ids_valid() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let chip_ids = vec![vec![0u8; 64], vec![1u8; 64]];
    let defects = validate_chip_ids(&chip_ids);
    assert!(defects.is_empty(), "{defects:#?}");
}

#[test]
fn test_validate_chip_ids_wrong_length() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

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
fn test_validate_rootfs_hash_valid() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let defects = validate_rootfs_hash("0123456789abcdefABCDEF");
    assert!(defects.is_empty(), "{defects:#?}");
}

#[test]
fn test_validate_rootfs_hash_invalid() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let defects = validate_rootfs_hash("not-hex!");
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["hexadecimal", "not-hex!"]);
}

#[test]
fn test_validate_rootfs_hash_empty_is_invalid() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    // Empty fingerprint should be rejected
    let defects = validate_rootfs_hash("");
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["empty"]);
}

#[test]
fn test_validate_base_guest_launch_measurements_none() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let defects = validate_base_guest_launch_measurements(&None);
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["base_guest_launch_measurements", "present"]);
}

#[test]
fn test_validate_base_guest_launch_measurements_empty() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![],
    };
    let defects = validate_base_guest_launch_measurements(&Some(measurements));
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert_contains_all_key_words(&defects[0], &["guest_launch_measurements", "empty"]);
}

#[test]
fn test_validate_base_guest_launch_measurements_valid() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let guest_launch_measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![GuestLaunchMeasurement {
            measurement: vec![0u8; 48],
            metadata: Some(GuestLaunchMeasurementMetadata {
                kernel_cmdline: Some("console=ttyS0".to_string()),
            }),
        }],
    };
    let defects = validate_base_guest_launch_measurements(&Some(guest_launch_measurements));
    assert!(defects.is_empty(), "{defects:#?}");
}

#[test]
fn test_validate_base_guest_launch_measurements_multiple_defects() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![
            // Valid measurement
            GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: Some("console=ttyS0".to_string()),
                }),
            },
            // Wrong measurement size
            GuestLaunchMeasurement {
                measurement: vec![0u8; 32],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: Some("console=ttyS0".to_string()),
                }),
            },
            // Missing metadata. This is ok.
            GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: None,
            },
            // Empty kernel_cmdline. This IS ok.
            GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: Some("".to_string()),
                }),
            },
        ],
    };

    let defects = validate_base_guest_launch_measurements(&Some(measurements));

    assert_eq!(defects.len(), 1, "{defects:#?}");

    assert_contains_all_key_words(&defects[0], &["guest_launch_measurements[1]", "48", "32"]);
}

#[test]
fn test_bless_alternative_guest_os_version_validate_valid() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: vec![vec![0u8; 64]],
        rootfs_hash: "abc123".to_string(),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: vec![GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: Some("console=ttyS0".to_string()),
                }),
            }],
        }),
    };

    assert_eq!(proposal.validate(), Ok(()));
}

#[test]
fn test_bless_alternative_guest_os_version_validate_multiple_errors() {
    let _guard = temporarily_enable_bless_alternative_guest_os_version_proposals();

    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: vec![],                     // Empty
        rootfs_hash: "not-hex!".to_string(),  // Invalid
        base_guest_launch_measurements: None, // Missing
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
            "hexadecimal",
            "base_guest_launch_measurements",
            "present",
        ],
    );
}

#[test]
fn test_bless_alternative_guest_os_version_disabled() {
    // Explicitly disable the flag - test that proposals are rejected when disabled
    let _guard = temporarily_disable_bless_alternative_guest_os_version_proposals();

    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: vec![vec![0u8; 64]],
        rootfs_hash: "abc123".to_string(),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: vec![GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: Some("console=ttyS0".to_string()),
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
        &["BlessAlternativeGuestOsVersion", "not enabled"],
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
        &["BlessAlternativeGuestOsVersion", "not enabled"],
    );
}
