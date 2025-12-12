use super::v1::{GuestLaunchMeasurement, GuestLaunchMeasurementMetadata, GuestLaunchMeasurements};
use hex;

#[test]
fn test_validate_guest_launch_measurement_valid() {
    let measurement_bytes = vec![0u8; 48];
    let measurement = GuestLaunchMeasurement {
        encoded_measurement: Some(hex::encode(&measurement_bytes)),
        #[allow(deprecated)]
        measurement: measurement_bytes,
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: "console=ttyS0".to_string(),
        }),
    };
    let result = measurement.validate();
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_validate_guest_launch_measurement_wrong_size() {
    let measurement_bytes = vec![0u8; 32];
    let measurement = GuestLaunchMeasurement {
        encoded_measurement: Some(hex::encode(&measurement_bytes)),
        #[allow(deprecated)]
        measurement: measurement_bytes,
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: "console=ttyS0".to_string(),
        }),
    };
    let defects = measurement.validate().unwrap_err();
    assert_eq!(defects.len(), 2, "{defects:#?}");
    assert!(
        defects[0].contains("48") && defects[0].contains("32"),
        "Expected error message to contain '48' and '32', got: {}",
        defects[0]
    );
    assert!(
        defects[1].contains("48") && defects[1].contains("32"),
        "Expected error message to contain '48' and '32', got: {}",
        defects[1]
    );
}

#[test]
fn test_validate_guest_launch_measurement_no_metadata() {
    let measurement_bytes = vec![0u8; 48];
    let measurement = GuestLaunchMeasurement {
        encoded_measurement: Some(hex::encode(&measurement_bytes)),
        #[allow(deprecated)]
        measurement: measurement_bytes,
        metadata: None,
    };
    let result = measurement.validate();
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_validate_guest_launch_measurement_empty_kernel_cmdline() {
    let measurement_bytes = vec![0u8; 48];
    let measurement = GuestLaunchMeasurement {
        encoded_measurement: Some(hex::encode(&measurement_bytes)),
        #[allow(deprecated)]
        measurement: measurement_bytes,
        metadata: Some(GuestLaunchMeasurementMetadata {
            kernel_cmdline: "".to_string(),
        }),
    };

    let defects = measurement.validate().unwrap_err();

    assert_eq!(defects.len(), 1, "{defects:#?}");
    assert!(
        defects[0].contains("kernel") && defects[0].contains("empty"),
        "Expected error message to contain 'kernel' and 'empty', got: {}",
        defects[0]
    );
}

#[test]
fn test_validate_guest_launch_measurement_multiple_defects() {
    let measurement_bytes = vec![0u8; 32]; // Wrong size.
    let measurement = GuestLaunchMeasurement {
        encoded_measurement: Some(hex::encode(&measurement_bytes)),
        #[allow(deprecated)]
        measurement: measurement_bytes,
        metadata: None, // No metadata.
    };
    let defects = measurement.validate().unwrap_err();
    // Should report measurement size error. Metadata missing is allowed though.
    assert_eq!(defects.len(), 2, "{defects:#?}");
    assert!(
        defects[0].contains("48"),
        "Expected error message to contain '48', got: {}",
        defects[0]
    );
    assert!(
        defects[1].contains("48"),
        "Expected error message to contain '48', got: {}",
        defects[1]
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
    let measurement_bytes = vec![0u8; 48];
    let guest_launch_measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![GuestLaunchMeasurement {
            encoded_measurement: Some(hex::encode(&measurement_bytes)),
            #[allow(deprecated)]
            measurement: measurement_bytes,
            metadata: Some(GuestLaunchMeasurementMetadata {
                kernel_cmdline: "console=ttyS0".to_string(),
            }),
        }],
    };
    let result = guest_launch_measurements.validate();
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_validate_guest_launch_measurements_multiple_defects() {
    let measurement_bytes = vec![0u8; 48];
    let measurement_bytes_short = vec![0u8; 32];
    let measurements = GuestLaunchMeasurements {
        guest_launch_measurements: vec![
            // Valid measurement
            GuestLaunchMeasurement {
                encoded_measurement: Some(hex::encode(&measurement_bytes)),
                #[allow(deprecated)]
                measurement: measurement_bytes.clone(),
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "console=ttyS0".to_string(),
                }),
            },
            // Wrong measurement size
            GuestLaunchMeasurement {
                encoded_measurement: Some(hex::encode(&measurement_bytes_short)),
                #[allow(deprecated)]
                measurement: measurement_bytes_short,
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "console=ttyS0".to_string(),
                }),
            },
            // Missing metadata. This is ok.
            GuestLaunchMeasurement {
                encoded_measurement: Some(hex::encode(&measurement_bytes)),
                #[allow(deprecated)]
                measurement: measurement_bytes.clone(),
                metadata: None,
            },
            // Empty kernel_cmdline. This is NOT ok, even though metadata is
            // optional.
            GuestLaunchMeasurement {
                encoded_measurement: Some(hex::encode(&measurement_bytes)),
                #[allow(deprecated)]
                measurement: measurement_bytes,
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "".to_string(),
                }),
            },
        ],
    };

    let defects = measurements.validate().unwrap_err();

    assert_eq!(defects.len(), 3, "{defects:#?}");

    assert!(
        defects[0].contains("guest_launch_measurements[1]")
            && defects[0].contains("48")
            && defects[0].contains("32"),
        "Expected error message to contain 'guest_launch_measurements[1]', '48', and '32', got: {}",
        defects[0]
    );

    assert!(
        defects[1].contains("guest_launch_measurements[1]")
            && defects[1].contains("48")
            && defects[1].contains("32"),
        "Expected error message to contain 'guest_launch_measurements[1]', '48', and '32', got: {}",
        defects[1]
    );

    assert!(
        defects[2].contains("guest_launch_measurements[3]")
            && defects[2].contains("kernel_cmdline")
            && defects[2].contains("empty"),
        "Expected error message to contain 'guest_launch_measurements[3]', 'kernel_cmdline', and 'empty', got: {}",
        defects[2]
    );
}
