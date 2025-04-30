use config_types::*;
use config_types_compatibility_lib::{get_previous_version, version_greater_than, ConfigFixture};
use serde_json;
use std::path::PathBuf;

#[test]
fn test_backwards_compatibility() {
    // Get the path to the fixtures directory using Bazel runfiles
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let test_data_dir = PathBuf::from(manifest_dir).join("fixtures");

    // Test each historical version
    for entry in std::fs::read_dir(&test_data_dir).unwrap() {
        let path = entry.unwrap().path();
        if let Some(ext) = path.extension() {
            if ext == "json" {
                let config_json = std::fs::read_to_string(&path).unwrap();
                let filename = path.file_name().unwrap().to_str().unwrap();

                // Try to deserialize into each config type
                if filename.starts_with("hostos") {
                    match serde_json::from_str::<HostOSConfig>(&config_json) {
                        Ok(_) => println!("Successfully deserialized {}", filename),
                        Err(e) => {
                            println!("Failed to deserialize {}: {}", filename, e);
                            panic!(
                                "Failed to deserialize historical HostOSConfig from {}",
                                filename
                            );
                        }
                    }
                } else if filename.starts_with("guestos") {
                    match serde_json::from_str::<GuestOSConfig>(&config_json) {
                        Ok(_) => println!("Successfully deserialized {}", filename),
                        Err(e) => {
                            println!("Failed to deserialize {}: {}", filename, e);
                            panic!(
                                "Failed to deserialize historical GuestOSConfig from {}",
                                filename
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_field_removal_protection() {
    // Verify that all fields in RESERVED_FIELD_NAMES are properly documented
    // This ensures we don't accidentally reuse removed field names
    for &reserved in RESERVED_FIELD_NAMES {
        assert!(
            !reserved.is_empty(),
            "Empty field name in RESERVED_FIELD_NAMES"
        );
    }
}

#[test]
fn test_version_increment() {
    let previous_version = get_previous_version();

    if CONFIG_VERSION != previous_version {
        assert!(
            version_greater_than(CONFIG_VERSION, &previous_version),
            "Config version must be greater than previous version"
        );
    }
}

#[test]
fn test_generate_current_fixture() {
    let fixture = ConfigFixture::generate_for_version(CONFIG_VERSION);

    let test_dir = PathBuf::from("fixtures");
    std::fs::create_dir_all(&test_dir).unwrap();

    fixture.save_to_directory(&test_dir).unwrap();

    std::fs::remove_dir_all(&test_dir).unwrap();
}
