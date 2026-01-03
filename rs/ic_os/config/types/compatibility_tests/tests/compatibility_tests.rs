use config_types::*;
use std::path::PathBuf;

#[test]
fn test_backwards_compatibility() {
    let test_data_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("fixtures");

    for entry in std::fs::read_dir(&test_data_dir).unwrap() {
        let path = entry.unwrap().path();
        let config_json = std::fs::read_to_string(&path).unwrap();
        let filename = path.file_name().unwrap().to_str().unwrap();

        if filename.starts_with("hostos_") {
            serde_json::from_str::<HostOSConfig>(&config_json).unwrap_or_else(|e| {
                panic!("Failed to deserialize historical HostOSConfig from {filename}: {e}")
            });
        } else if filename.starts_with("guestos_") {
            serde_json::from_str::<GuestOSConfig>(&config_json).unwrap_or_else(|e| {
                panic!("Failed to deserialize historical GuestOSConfig from {filename}: {e}")
            });
        }

        println!("Successfully deserialized {filename}");
    }
}
