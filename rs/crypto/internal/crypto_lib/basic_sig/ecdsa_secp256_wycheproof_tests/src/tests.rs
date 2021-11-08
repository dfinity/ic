//! Adapted from [OpenSK](https://github.com/google/OpenSK/)
#![allow(clippy::unwrap_used)]
use openssl::sha::sha256;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use ic_crypto_internal_basic_sig_ecdsa_secp256k1 as ecdsa_secp256k1;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1 as ecdsa_secp256r1;
use std::convert::TryFrom;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Wycheproof {
    algorithm: String,
    #[allow(dead_code)]
    generatorVersion: String,
    #[allow(dead_code)]
    numberOfTests: u32,
    #[allow(dead_code)]
    header: Vec<String>,
    notes: HashMap<String, String>,
    schema: String,
    testGroups: Vec<TestGroup>,
}

impl Wycheproof {
    fn type_check<F>(&self, key_type_check: F)
    where
        F: Fn(&Key) + Copy,
    {
        assert_eq!(self.algorithm, "ECDSA");
        assert_eq!(self.schema, "ecdsa_p1363_verify_schema.json");
        for group in &self.testGroups {
            group.type_check(key_type_check);
        }
    }

    fn run_tests<F>(&self, tester: F) -> bool
    where
        F: Fn(&TestGroup, &HashMap<String, String>) -> bool,
    {
        let mut result = true;
        for group in &self.testGroups {
            result &= tester(group, &self.notes);
        }
        result
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct TestGroup {
    key: Key,
    #[allow(dead_code)]
    keyDer: String, // hex
    #[allow(dead_code)]
    keyPem: String,
    sha: String,
    r#type: String,
    tests: Vec<TestCase>,
}

impl TestGroup {
    fn type_check<F>(&self, key_type_check: F)
    where
        F: Fn(&Key),
    {
        key_type_check(&self.key);

        assert_eq!(self.sha, "SHA-256");
        assert_eq!(self.r#type, "EcdsaP1363Verify");
    }
}

#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types)]
enum TestResult {
    valid,
    invalid,
    acceptable,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct TestCase {
    tcId: u32,
    comment: String,
    msg: String,
    sig: String, // hex
    result: TestResult,
    flags: Vec<String>,
}

impl TestCase {
    fn print(&self, notes: &HashMap<String, String>, error_msg: &str) {
        println!("Test case #{} => {}", self.tcId, error_msg);
        println!("    {}", self.comment);
        println!("    result = {:?}", self.result);
        for f in &self.flags {
            println!(
                "    flag {} = {}",
                f,
                notes.get(f).map_or("unknown flag", |x| x)
            );
        }
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Key {
    curve: String,
    keySize: u32,
    r#type: String,
    uncompressed: String,
    #[allow(dead_code)]
    wx: String,
    #[allow(dead_code)]
    wy: String,
}

#[test]
fn wycheproof_ecdsa_secp256k1_sha256_p1363() {
    let wycheproof = load_tests("test_resources/ecdsa_secp256k1_sha256_p1363_test.json").unwrap();
    wycheproof.type_check(type_check_k1);
    assert!(wycheproof.run_tests(run_tests_k1));
}

fn load_tests(file_path: &str) -> Result<Wycheproof, Box<dyn Error>> {
    let path = {
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push(file_path);
        path
    };
    let file = File::open(path)?;
    let wycheproof = serde_json::from_reader(BufReader::new(file))?;
    Ok(wycheproof)
}

fn type_check_k1(key: &Key) {
    assert_eq!(key.curve, "secp256k1");
    assert_eq!(key.keySize, 256);
    assert_eq!(key.r#type, "EcPublicKey");
    assert_eq!(key.uncompressed.len(), 130);
}

fn run_tests_k1(group: &TestGroup, notes: &HashMap<String, String>) -> bool {
    let pk = match ecdsa_secp256k1::api::public_key_from_der(&hex::decode(&group.keyDer).unwrap()) {
        Err(_) => None,
        Ok(pk) => Some(pk),
    };
    let mut result = true;
    for test in &group.tests {
        let case_result = run_test_k1(test, &pk, notes);
        result &= case_result;
    }
    result
}

fn run_test_k1(
    test: &TestCase,
    pk: &Option<ecdsa_secp256k1::types::PublicKeyBytes>,
    notes: &HashMap<String, String>,
) -> bool {
    match pk {
        None => {
            let pass = match test.result {
                TestResult::invalid | TestResult::acceptable => true,
                TestResult::valid => false,
            };
            if !pass {
                test.print(notes, "Invalid public key");
            }
            pass
        }
        Some(pk) => {
            let msg = hex::decode(&test.msg).unwrap();
            let sig = hex::decode(&test.sig).unwrap();
            match ecdsa_secp256k1::types::SignatureBytes::try_from(sig) {
                Err(e) => {
                    let pass = match test.result {
                        TestResult::invalid | TestResult::acceptable => true,
                        TestResult::valid => false,
                    };
                    if !pass {
                        test.print(notes, "Invalid IEEE P1363 encoding for the signature");
                        println!("    {:?}", e);
                    }
                    pass
                }
                Ok(sig_bytes) => {
                    let msg_hash = sha256(&msg);
                    let verified = ecdsa_secp256k1::api::verify(&sig_bytes, &msg_hash, pk).is_ok();
                    let pass = match test.result {
                        TestResult::acceptable => true,
                        TestResult::valid => verified,
                        TestResult::invalid => !verified,
                    };
                    if !pass {
                        test.print(
                            notes,
                            &format!(
                                "Expected {:?} result, but the signature verification was {}",
                                test.result, verified
                            ),
                        );
                    }
                    pass
                }
            }
        }
    }
}

#[test]
fn wycheproof_ecdsa_secp256r1_sha256_p1363() {
    let wycheproof = load_tests("test_resources/ecdsa_secp256r1_sha256_p1363_test.json").unwrap();
    wycheproof.type_check(type_check_r1);
    assert!(wycheproof.run_tests(run_tests_r1));
}

fn type_check_r1(key: &Key) {
    assert_eq!(key.curve, "secp256r1");
    assert_eq!(key.keySize, 256);
    assert_eq!(key.r#type, "EcPublicKey");
    assert_eq!(key.uncompressed.len(), 130);
}

fn run_tests_r1(group: &TestGroup, notes: &HashMap<String, String>) -> bool {
    let pk = match ecdsa_secp256r1::api::public_key_from_der(&hex::decode(&group.keyDer).unwrap()) {
        Err(_) => None,
        Ok(pk) => Some(pk),
    };
    let mut result = true;
    for test in &group.tests {
        let case_result = run_test_r1(test, &pk, notes);
        result &= case_result;
    }
    result
}

fn run_test_r1(
    test: &TestCase,
    pk: &Option<ecdsa_secp256r1::types::PublicKeyBytes>,
    notes: &HashMap<String, String>,
) -> bool {
    match pk {
        None => {
            let pass = match test.result {
                TestResult::invalid | TestResult::acceptable => true,
                TestResult::valid => false,
            };
            if !pass {
                test.print(notes, "Invalid public key");
            }
            pass
        }
        Some(pk) => {
            let msg = hex::decode(&test.msg).unwrap();
            let sig = hex::decode(&test.sig).unwrap();
            match ecdsa_secp256r1::types::SignatureBytes::try_from(sig) {
                Err(e) => {
                    let pass = match test.result {
                        TestResult::invalid | TestResult::acceptable => true,
                        TestResult::valid => false,
                    };
                    if !pass {
                        test.print(notes, "Invalid IEEE P1363 encoding for the signature");
                        println!("    {:?}", e);
                    }
                    pass
                }
                Ok(sig_bytes) => {
                    let msg_hash = sha256(&msg);
                    let verified = ecdsa_secp256r1::api::verify(&sig_bytes, &msg_hash, pk).is_ok();
                    let pass = match test.result {
                        TestResult::acceptable => true,
                        TestResult::valid => verified,
                        TestResult::invalid => !verified,
                    };
                    if !pass {
                        test.print(
                            notes,
                            &format!(
                                "Expected {:?} result, but the signature verification was {}",
                                test.result, verified
                            ),
                        );
                    }
                    pass
                }
            }
        }
    }
}
