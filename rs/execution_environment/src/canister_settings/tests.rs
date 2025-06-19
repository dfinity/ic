use super::*;
use crate::canister_settings::EnvironmentVariables;
use std::collections::BTreeMap;

fn calculate_hash(env_vars: BTreeMap<String, String>) -> Vec<u8> {
    let mut hashes: Vec<Vec<u8>> = Vec::new();
    for (key, value) in &env_vars {
        let mut key_hash = Sha256::hash(key.as_bytes()).to_vec();
        let mut value_hash = Sha256::hash(value.as_bytes()).to_vec();
        key_hash.append(&mut value_hash);
        hashes.push(key_hash);
    }
    hashes.sort();
    Sha256::hash(hashes.concat().as_slice()).to_vec()
}

#[test]
fn test_calculate_hash_of_environment_variables() {
    let env_vars = BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "info".to_string()),
    ]);
    let env_vars_hash = EnvironmentVariables::new(env_vars.clone()).hash();
    assert_eq!(env_vars_hash, calculate_hash(env_vars));
}

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
