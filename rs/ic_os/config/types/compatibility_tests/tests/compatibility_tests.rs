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
                panic!(
                    "Failed to deserialize historical HostOSConfig from borrowed {filename}: {e}"
                )
            });

            // Exercise DeserializeOwned using serde_json::from_reader. This is
            // the main entrypoint of this code, in practice.
            let config = serde_json::from_reader::<_, HostOSConfig>(config_json.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to deserialize historical HostOSConfig from owned {filename}: {e}"
                    )
                });

            serde_json::to_string_pretty(&config).unwrap_or_else(|e| {
                panic!("Failed to serialize HostOSConfig sourced from {filename}: {e}")
            });
        } else if filename.starts_with("guestos_") {
            serde_json::from_str::<GuestOSConfig>(&config_json).unwrap_or_else(|e| {
                panic!(
                    "Failed to deserialize historical GuestOSConfig from borrowed {filename}: {e}"
                )
            });

            // Exercise DeserializeOwned using serde_json::from_reader. This is
            // the main entrypoint of this code, in practice.
            let config = serde_json::from_reader::<_, GuestOSConfig>(config_json.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to deserialize historical GuestOSConfig from owned {filename}: {e}"
                    )
                });

            serde_json::to_string_pretty(&config).unwrap_or_else(|e| {
                panic!("Failed to serialize GuestOSConfig sourced from {filename}: {e}")
            });
        }

        println!("Successfully deserialized {filename}");
    }
}
