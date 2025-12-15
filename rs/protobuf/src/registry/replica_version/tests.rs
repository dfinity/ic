use super::v1::{GuestLaunchMeasurement, GuestLaunchMeasurementMetadata, GuestLaunchMeasurements};

#[test]
fn test_validate_guest_launch_measurement_valid() {
    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 48],
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: Some("console=ttyS0".to_string()),
        }),
    };
    let result = measurement.validate();
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_validate_guest_launch_measurement_wrong_size() {
    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 32],
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: Some("console=ttyS0".to_string()),
        }),
    };
    let defects = measurement.validate().unwrap_err();
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert!(
        defects[0].contains("48") && defects[0].contains("32"),
        "Expected error message to contain '48' and '32', got: {}",
        defects[0]
    );
}

#[test]
fn test_validate_guest_launch_measurement_no_metadata() {
    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 48],
        metadata: None,
    };
    let result = measurement.validate();
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_validate_guest_launch_measurement_empty_kernel_cmdline() {
    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 48],
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: Some("".to_string()),
        }),
    };

    assert_eq!(measurement.validate(), Ok(()));
}

#[test]
fn test_validate_guest_launch_measurement_multiple_defects() {
    let measurement = GuestLaunchMeasurement {
        measurement: vec![0u8; 32], // Wrong size.
        metadata: None,             // No metadata.
    };
    let defects = measurement.validate().unwrap_err();
    // Should report measurement size error. Metadata missing is allowed though.
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert!(
        defects[0].contains("48"),
        "Expected error message to contain '48', got: {}",
        defects[0]
    );
}

#[test]
fn test_validate_guest_launch_measurements_empty() {
    let measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![],
    };
    let defects = measurements.validate().unwrap_err();
    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert!(
        defects[0].contains("guest_launch_measurements") && defects[0].contains("empty"),
        "Expected error message to contain 'guest_launch_measurements' and 'empty', got: {}",
        defects[0]
    );
}

#[test]
fn test_validate_guest_launch_measurements_valid() {
    let guest_launch_measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![GuestLaunchMeasurement {
            measurement: vec![0u8; 48],
            metadata: Some(GuestLaunchMeasurementMetadata {
                kernel_cmdline: Some("console=ttyS0".to_string()),
            }),
        }],
    };
    let result = guest_launch_measurements.validate();
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_validate_guest_launch_measurements_multiple_defects() {
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
            // Metadata absent. This is OK.
            GuestLaunchMeasurement {
                measurement: vec![0u8; 48],
                metadata: None,
            },
        ],
    };

    let defects = measurements.validate().unwrap_err();

    // 1 defect expected: bad measurement length.
    assert_eq!(defects.len(), 1, "{defects:#?}");

    assert!(
        defects[0].contains("guest_launch_measurements[1]")
            && defects[0].contains("48")
            && defects[0].contains("32"),
        "Expected error message to contain 'guest_launch_measurements[1]', '48', and '32', got: {}",
        defects[0]
    );
}
