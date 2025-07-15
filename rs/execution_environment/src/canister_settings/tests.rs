use crate::canister_settings::EnvironmentVariables;
use ic_crypto_sha2::Sha256;
use std::collections::BTreeMap;

#[test]
fn test_environment_variables_hash_is_deterministic() {
    let env_vars = BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "info".to_string()),
    ]);
    let env_vars_hash_1 = EnvironmentVariables::new(env_vars.clone()).hash();

    let env_vars = BTreeMap::from([
        ("LOG_LEVEL".to_string(), "info".to_string()),
        ("NODE_ENV".to_string(), "production".to_string()),
    ]);
    let env_vars_hash_2 = EnvironmentVariables::new(env_vars.clone()).hash();
    assert_eq!(env_vars_hash_1, env_vars_hash_2);
}

#[test]
fn test_environment_variables_hash_empty_env_vars() {
    let env_vars = BTreeMap::new();
    let hash = EnvironmentVariables::new(env_vars).hash();
    // SHA256 of empty input.
    let expected = Sha256::hash(&[]);
    assert_eq!(hash, expected);
}

#[test]
fn test_environment_variables_hash_single_pair() {
    let env_vars = BTreeMap::from([("KEY".to_string(), "VALUE".to_string())]);
    let hash = EnvironmentVariables::new(env_vars).hash();

    let key_hash = Sha256::hash("KEY".as_bytes());
    let value_hash = Sha256::hash("VALUE".as_bytes());

    let mut hasher = Sha256::new();
    hasher.write(&key_hash);
    hasher.write(&value_hash);
    let expected = hasher.finish();

    assert_eq!(hash, expected);
}

#[test]
fn test_environment_variables_hash_value_change_produces_different_hash() {
    let original = BTreeMap::from([("API_KEY".to_string(), "abc123".to_string())]);
    let changed = BTreeMap::from([("API_KEY".to_string(), "xyz789".to_string())]);
    let hash1 = EnvironmentVariables::new(original).hash();
    let hash2 = EnvironmentVariables::new(changed).hash();
    assert_ne!(hash1, hash2);
}

#[test]
fn test_environment_variables_hash_output() {
    let env_vars = BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "debug".to_string()),
        ("API_KEY".to_string(), "1234567890abcdef".to_string()),
    ]);

    // 1. Manually compute expected hash using the algorithm step-by-step.
    let mut intermediate_hashes = vec![];

    for (key, value) in &env_vars {
        let key_hash = Sha256::hash(key.as_bytes());
        let value_hash = Sha256::hash(value.as_bytes());

        let mut combined = key_hash.to_vec();
        combined.extend_from_slice(&value_hash);
        intermediate_hashes.push(combined);
    }

    // 2. Sort intermediate hashes lexicographically.
    intermediate_hashes.sort();

    // 3. Concatenate and hash the result.
    let mut hasher = Sha256::new();
    for pair_hash in &intermediate_hashes {
        hasher.write(pair_hash);
    }
    let expected = hasher.finish();

    // Verify that the actual hash matches the expected hash.
    let actual = EnvironmentVariables::new(env_vars).hash();
    assert_eq!(actual, expected);
}
