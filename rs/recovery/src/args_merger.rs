use serde_json::Value;
use slog::{Logger, warn};

/// Merges two serializable objects ignoring all the None values of [new]. For each field where
/// there is a difference between the old and the new value, will emit a warning with the
/// new value.
pub fn merge<T>(logger: &Logger, label: &str, old: &T, new: &T) -> Result<T, serde_json::Error>
where
    T: Clone + for<'a> serde::Deserialize<'a> + serde::Serialize,
{
    serde_json::from_value(merge_values(
        logger,
        label,
        serde_json::to_value(old.clone()).unwrap(),
        serde_json::to_value(new.clone()).unwrap(),
    ))
}

fn merge_values(logger: &Logger, label: &str, old: Value, new: Value) -> Value {
    match (old, new) {
        (old, Value::Null) => old,
        (Value::Object(old), Value::Object(new)) => {
            let mut merged = old.clone();

            for (key, new_value) in new {
                if !new_value.is_null() {
                    let old_value = old.get(&key).unwrap_or(&Value::Null).clone();
                    merged.insert(
                        key.clone(),
                        merge_values(logger, &key, old_value, new_value),
                    );
                }
            }

            Value::Object(merged)
        }
        (old_value, new_value) => {
            if old_value != new_value {
                warn!(
                    logger,
                    "Value of {} has changed. Old: {}, new: {}", label, old_value, new_value
                );
            }
            new_value
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use url::Url;

    use crate::{RecoveryArgs, util};

    use super::*;

    #[test]
    fn merge_test() {
        let logger = util::make_logger();

        let args1 = RecoveryArgs {
            dir: PathBuf::from("/dir1/"),
            nns_url: Url::parse("https://fake_nns_url.com/").unwrap(),
            replica_version: None,
            admin_key_file: Some(PathBuf::from("/dir1/key_file")),
            test_mode: true,
            skip_prompts: true,
            use_local_binaries: false,
        };
        let args2 = RecoveryArgs {
            dir: PathBuf::from("/dir2/"),
            nns_url: Url::parse("https://fake_nns_url.com/").unwrap(),
            replica_version: None,
            admin_key_file: None,
            test_mode: false,
            skip_prompts: true,
            use_local_binaries: false,
        };

        let expected = RecoveryArgs {
            dir: args2.dir.clone(),
            nns_url: args2.nns_url.clone(),
            replica_version: args2.replica_version.clone(),
            admin_key_file: args1.admin_key_file.clone(),
            test_mode: args2.test_mode,
            skip_prompts: true,
            use_local_binaries: false,
        };

        assert_eq!(expected, merge(&logger, "test", &args1, &args2).unwrap());
    }
}
