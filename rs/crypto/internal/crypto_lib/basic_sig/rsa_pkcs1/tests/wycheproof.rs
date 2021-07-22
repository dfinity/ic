use ic_crypto_internal_basic_sig_rsa_pkcs1::*;
use serde::{de::Error, Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};

#[test]
fn should_pass_wycheproof_tests() {
    execute_wycheproof_tests(include_bytes!("data/rsa_signature_2048_sha256_test.json"));
    execute_wycheproof_tests(include_bytes!("data/rsa_signature_3072_sha256_test.json"));
    execute_wycheproof_tests(include_bytes!("data/rsa_signature_test.json"));
}

fn execute_wycheproof_tests(test_data: &[u8]) {
    let tests: WycheproofTestSet =
        serde_json::from_slice(test_data).expect("Test data was not valid JSON");

    /*
    Currently Wycheproof RSA tests have three possible flags:

    * `SmallModulus`: the public modulus is under 2048 bits. We ignore
       such tests as MINIMUM_RSA_KEY_SIZE is 2048 bits.
    * `SmallPublicKey`: the public exponent is small. We accept this.
    * `MissingNull`: the signature uses an obsolete alternative PKCS1v1.5
      encoding that is supported by some systems. We do not support this
      and expect such signatures to not verify.
    */

    assert_eq!(tests.algorithm, "RSASSA-PKCS1-v1_5");

    for group in tests.test_groups {
        assert_eq!(group.typ, "RsassaPkcs1Verify");

        if group.sha != "SHA-256" {
            continue;
        }

        if group.keysize < RsaPublicKey::MINIMUM_RSA_KEY_SIZE {
            continue;
        }

        if group.keysize > RsaPublicKey::MAXIMUM_RSA_KEY_SIZE {
            continue;
        }

        let key = RsaPublicKey::from_der_spki(&group.key_der).expect("Unable to parse test key");

        let key_from_components =
            RsaPublicKey::from_components(&group.e, &group.n).expect("Unable to parse test key");

        assert_eq!(key.as_der(), key_from_components.as_der());

        for test in group.tests {
            let expected_result = match test.result {
                WycheproofResult::Valid => {
                    assert_eq!(test.flags.len(), 0);
                    true
                }
                WycheproofResult::Invalid => {
                    assert_eq!(test.flags.len(), 0);
                    false
                }
                WycheproofResult::Acceptable => {
                    !test.flags.contains(&WycheproofRsaFlags::MissingNull)
                }
            };

            match key.verify_pkcs1_sha256(&test.msg, &test.sig) {
                Ok(_) => assert!(expected_result),
                Err(_) => assert!(!expected_result),
            }
        }
    }
}

fn from_hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    hex::decode(s).map_err(D::Error::custom)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum WycheproofResult {
    Valid,
    Invalid,
    Acceptable,
}

impl<'de> Deserialize<'de> for WycheproofResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &str = Deserialize::deserialize(deserializer)?;

        match s {
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "acceptable" => Ok(Self::Acceptable),
            unknown => Err(D::Error::custom(format!(
                "unexpected 'result' value {}",
                unknown
            ))),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum WycheproofRsaFlags {
    /// Public modulus is under 2048 bits
    SmallModulus,
    /// Public exponent is under 65537
    SmallPublicKey,
    /// PKCS1v1.5 signature is missing NULL in the encoded AlgorithmIdentifier
    MissingNull,
}

impl<'de> Deserialize<'de> for WycheproofRsaFlags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &str = Deserialize::deserialize(deserializer)?;

        match s {
            "SmallModulus" => Ok(Self::SmallModulus),
            "SmallPublicKey" => Ok(Self::SmallPublicKey),
            "MissingNull" => Ok(Self::MissingNull),
            unknown => Err(D::Error::custom(format!(
                "unexpected flag value {}",
                unknown
            ))),
        }
    }
}

#[derive(Deserialize, Debug)]
struct WycheproofTest {
    #[serde(rename = "tcId")]
    tc_id: usize,
    comment: String,
    #[serde(deserialize_with = "from_hex")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "from_hex")]
    sig: Vec<u8>,
    result: WycheproofResult,
    flags: HashSet<WycheproofRsaFlags>,
}

#[derive(Deserialize, Debug)]
struct WycheproofJwk {
    alg: String,
    e: String,
    kid: String,
    kty: String,
    n: String,
}

#[derive(Deserialize, Debug)]
struct WycheproofTestGroup {
    #[serde(deserialize_with = "from_hex")]
    e: Vec<u8>,
    #[serde(rename = "keyAsn", deserialize_with = "from_hex")]
    key_asn1: Vec<u8>,
    #[serde(rename = "keyDer", deserialize_with = "from_hex")]
    key_der: Vec<u8>,
    #[serde(rename = "keyJwk")]
    key_jwk: WycheproofJwk,
    #[serde(rename = "keyPem")]
    key_pem: String,
    keysize: usize,
    #[serde(deserialize_with = "from_hex")]
    n: Vec<u8>,
    sha: String,
    #[serde(rename = "type")]
    typ: String,
    tests: Vec<WycheproofTest>,
}

#[derive(Deserialize, Debug)]
struct WycheproofTestSet {
    algorithm: String,
    #[serde(rename = "generatorVersion")]
    generator_version: String,
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    header: Vec<String>,
    notes: HashMap<String, String>,
    schema: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofTestGroup>,
}
