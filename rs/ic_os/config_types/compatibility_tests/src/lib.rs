use std::path::PathBuf;

mod fixture;

pub use fixture::ConfigFixture;

pub fn version_greater_than(v1: &str, v2: &str) -> bool {
    let v1_parts: Vec<u32> = v1.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    let v2_parts: Vec<u32> = v2.split('.').map(|s| s.parse().unwrap_or(0)).collect();

    v1_parts
        .iter()
        .zip(v2_parts.iter())
        .find(|(&a, &b)| a != b)
        .map(|(a, b)| a > b)
        .unwrap_or(false)
}

pub fn get_previous_version() -> String {
    let fixtures_dir = PathBuf::from("fixtures");

    let mut versions = Vec::new();
    for entry in std::fs::read_dir(fixtures_dir).unwrap() {
        let path = entry.unwrap().path();
        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            if (filename.starts_with("hostos_v") || filename.starts_with("guestos_v"))
                && filename.ends_with(".json")
            {
                let version = if filename.starts_with("hostos_v") {
                    filename[7..filename.len() - 5].to_string()
                } else {
                    filename[8..filename.len() - 5].to_string()
                };
                versions.push(version);
            }
        }
    }

    versions.sort_by(|a, b| {
        let a_parts: Vec<u32> = a.split('.').map(|s| s.parse().unwrap_or(0)).collect();
        let b_parts: Vec<u32> = b.split('.').map(|s| s.parse().unwrap_or(0)).collect();
        b_parts.cmp(&a_parts)
    });

    versions
        .first()
        .cloned()
        .unwrap_or_else(|| "1.0.0".to_string())
}
