use super::*;

use ic_protobuf::registry::replica_version::v1::{
    GuestLaunchMeasurement, GuestLaunchMeasurementMetadata,
};

const REPLICA_VERSION_ID: &str = "eb3ab997954f2a91db8a42f84132cf37078d481c";
const RELEASE_PACKAGE_SHA256_HEX: &str =
    "C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEED00D";
const RELEASE_PACKAGE_URL: &str = "http://release_package.tar.zst";

fn guest_launch_measurements() -> GuestLaunchMeasurements {
    GuestLaunchMeasurements {
        guest_launch_measurements: vec![GuestLaunchMeasurement {
            measurement: vec![0x42; 48],
            metadata: Some(GuestLaunchMeasurementMetadata {
                kernel_cmdline: Some("foo=bar".to_string()),
                vcpu_type: None,
            }),
        }],
    }
}

/// Returns a payload that elects one version. The launch measurements are left
/// for the caller to fill in, because that is what the tests here vary.
fn new_elect_payload(
    guest_launch_measurements: Option<GuestLaunchMeasurements>,
) -> ReviseElectedGuestosVersionsPayload {
    ReviseElectedGuestosVersionsPayload {
        replica_version_to_elect: Some(REPLICA_VERSION_ID.to_string()),
        release_package_sha256_hex: Some(RELEASE_PACKAGE_SHA256_HEX.to_string()),
        release_package_urls: vec![RELEASE_PACKAGE_URL.to_string()],
        guest_launch_measurements,
        replica_versions_to_unelect: vec![],
    }
}

#[test]
fn test_electing_a_version_with_launch_measurements_is_valid() {
    let payload = new_elect_payload(Some(guest_launch_measurements()));
    let result = payload.validate();
    assert_eq!(result, Ok(()));
}

/// Launch measurements are one of the parameters that electing a version
/// requires, so leaving them out makes the payload incomplete.
#[test]
fn test_electing_a_version_without_launch_measurements_is_rejected() {
    let payload = new_elect_payload(None);
    let result = payload.validate();
    let defect = result.unwrap_err().to_lowercase();
    for key_word in [
        "all parameters",
        "missing parameters: [\"guest_launch_measurements\"]",
    ] {
        assert!(defect.contains(key_word), "{key_word} not in {defect}");
    }
}

#[test]
fn test_electing_a_version_with_empty_launch_measurements_is_rejected() {
    let payload = new_elect_payload(Some(GuestLaunchMeasurements {
        guest_launch_measurements: vec![],
    }));

    let result = payload.validate();

    let defect = result.unwrap_err().to_lowercase();
    for key_word in ["guest_launch_measurements", "empty"] {
        assert!(defect.contains(key_word), "{key_word} not in {defect}");
    }
}

#[test]
fn test_electing_a_version_with_invalid_launch_measurement_is_rejected() {
    // An SEV-SNP measurement is 48 bytes long, not 3.
    let payload = new_elect_payload(Some(GuestLaunchMeasurements {
        guest_launch_measurements: vec![GuestLaunchMeasurement {
            measurement: vec![0x42; 3],
            metadata: None,
        }],
    }));

    let result = payload.validate();

    let defect = result.unwrap_err().to_lowercase();
    for key_word in ["guest_launch_measurements", "48 bytes"] {
        assert!(defect.contains(key_word), "{key_word} not in {defect}");
    }
}

/// Launch measurements are only required when a version is elected. Unelecting
/// does not involve any GuestOS image.
#[test]
fn test_unelecting_a_version_without_launch_measurements_is_valid() {
    let payload = ReviseElectedGuestosVersionsPayload {
        replica_version_to_elect: None,
        release_package_sha256_hex: None,
        release_package_urls: vec![],
        guest_launch_measurements: None,
        replica_versions_to_unelect: vec![REPLICA_VERSION_ID.to_string()],
    };

    let result = payload.validate();

    assert_eq!(result, Ok(()));
}

/// Launch measurements only mean something for a version that is being
/// elected. On an unelect-only payload they would be silently dropped, so they
/// are reported as a defect instead.
#[test]
fn test_unelecting_a_version_with_launch_measurements_is_rejected() {
    let payload = ReviseElectedGuestosVersionsPayload {
        guest_launch_measurements: Some(guest_launch_measurements()),
        replica_versions_to_unelect: vec![REPLICA_VERSION_ID.to_string()],
        ..Default::default()
    };

    let result = payload.validate();

    let defect = result.unwrap_err().to_lowercase();
    for key_word in [
        "all parameters",
        "replica_version_to_elect",
        "release_package_sha256_hex",
        "release_package_urls",
    ] {
        assert!(defect.contains(key_word), "{key_word} not in {defect}");
    }
}

#[test]
fn test_neither_electing_nor_unelecting_is_rejected() {
    let payload = ReviseElectedGuestosVersionsPayload::default();

    let result = payload.validate();

    let defect = result.unwrap_err().to_lowercase();
    for key_word in ["at least one version", "elected or unelected"] {
        assert!(defect.contains(key_word), "{key_word} not in {defect}");
    }
}

#[test]
fn test_incomplete_election_parameters_are_rejected() {
    // The release package hash and URLs are missing.
    let payload = ReviseElectedGuestosVersionsPayload {
        replica_version_to_elect: Some(REPLICA_VERSION_ID.to_string()),
        guest_launch_measurements: Some(guest_launch_measurements()),
        ..Default::default()
    };

    let result = payload.validate();

    let defect = result.unwrap_err().to_lowercase();
    for key_word in [
        "all parameters",
        "release_package_sha256_hex",
        "release_package_urls",
    ] {
        assert!(defect.contains(key_word), "{key_word} not in {defect}");
    }
}
