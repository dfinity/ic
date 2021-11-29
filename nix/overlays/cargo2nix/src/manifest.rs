use toml::value::Table;

use serde::Deserialize;
use std::collections::BTreeMap;

pub type TomlProfile = BTreeMap<String, Table>;

pub fn extract_profiles(manifest_contents: &[u8]) -> TomlProfile {
    #[derive(Debug, Deserialize)]
    struct Manifest {
        pub profile: Option<TomlProfile>,
    }

    toml::from_slice::<Manifest>(manifest_contents)
        .ok()
        .and_then(|m| m.profile)
        .map(|mut profiles_by_name| {
            remove_panic(&mut profiles_by_name);
            profiles_by_name
        })
        .unwrap_or_default()
}

// Remove the `panic` key from `test` and `bench` profiles, which is ignored by `cargo`.
fn remove_panic(profiles_by_name: &mut TomlProfile) {
    for (name, profile) in profiles_by_name.iter_mut() {
        if name == "test" || name == "bench" {
            profile.remove("panic");
        }
    }
}
