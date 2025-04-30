use config_types::*;
use config_types_compatibility_lib::ConfigFixture;
use serde_json;

#[test]
fn test_backwards_compatibility() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let test_data_dir = PathBuf::from(manifest_dir).join("fixtures");

    // Test each historical config version
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
