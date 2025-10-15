use crate::address::DogecoinAddress;
use crate::lifecycle::init::Network;
use assert_matches::assert_matches;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::BufReader;
use std::path::PathBuf;

// Content copied from https://github.com/dogecoin/dogecoin/blob/2c513d0172e8bc86fe9a337693b26f2fdf68a013/src/test/data/base58_keys_valid.json
const VALID_BASE58_KEYS: &str = "base58_keys_valid.json";
// Content copied from https://github.com/dogecoin/dogecoin/blob/2c513d0172e8bc86fe9a337693b26f2fdf68a013/src/test/data/base58_keys_invalid.json
const INVALID_BASE58_KEYS: &str = "base58_keys_invalid.json";

#[test]
fn should_parse_valid_addresses() {
    let test_cases: Vec<KeyPayload> = test_vectors(VALID_BASE58_KEYS);
    assert_eq!(test_cases.len(), 50);

    for test_case in test_cases {
        if !test_case.is_private_key() {
            let parsed_address =
                DogecoinAddress::parse(test_case.base58_address(), &test_case.network())
                    .unwrap_or_else(|e| {
                        panic!("Failed to parse valid public key {test_case:?}: {e:?}")
                    });

            assert_eq!(parsed_address.as_bytes(), test_case.expected_bytes());
            assert_matches!(
                (&parsed_address, test_case.expect_address_type()),
                (DogecoinAddress::P2pkh(_), AddressType::Pubkey)
                    | (DogecoinAddress::P2sh(_), AddressType::Script)
            );

            let rendered_parsed_address = parsed_address.display(&test_case.network());
            assert_eq!(test_case.base58_address(), rendered_parsed_address);
        }
    }
}

#[test]
fn should_fail_to_parse_invalid_addresses() {
    const ALL_NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Regtest];

    let test_cases: Vec<_> = test_vectors::<Vec<Vec<InvalidKey>>>(INVALID_BASE58_KEYS)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(test_cases.len(), 50);

    for test_case in test_cases {
        for network in &ALL_NETWORKS {
            assert_matches!(DogecoinAddress::parse(&test_case.0, network), Err(_));
        }
    }
}

fn test_vectors<T: DeserializeOwned>(filename: &str) -> T {
    // Return something like "rs/dogecoin/ckdoge/minter/test_vectors/base58_keys_invalid.json rs/dogecoin/ckdoge/minter/test_vectors/base58_keys_valid.json"
    let test_vector_files = std::env::var("TEST_VECTORS").expect(
        "environment variable 'TEST_VECTORS' should be a space-separated list of test vectors",
    );
    let file = test_vector_files
        .split(" ")
        .map(PathBuf::from)
        .find(|f| f.file_name().is_some_and(|file_name| file_name == filename))
        .unwrap_or_else(|| {
            panic!("Could not find test vectors {filename}, check 'TEST_VECTORS' is set correctly")
        });
    let display = file.display();
    let file = std::fs::File::open(&file)
        .unwrap_or_else(|err| panic!("Failed to open file {}: {}", display, err));
    serde_json::from_reader(BufReader::new(file))
        .unwrap_or_else(|err| panic!("Failed to deserialize file {}: {}", display, err))
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct KeyPayload(String, String, KeyProperties);

impl KeyPayload {
    pub fn base58_address(&self) -> &str {
        &self.0
    }

    pub fn expected_bytes(&self) -> Vec<u8> {
        hex::decode(&self.1).unwrap()
    }

    pub fn is_private_key(&self) -> bool {
        self.2.is_privkey
    }

    pub fn network(&self) -> Network {
        if self.2.is_testnet {
            return Network::Testnet;
        }
        Network::Mainnet
    }

    pub fn expect_address_type(&self) -> AddressType {
        self.2.address_type.unwrap()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct KeyProperties {
    #[serde(rename = "addrType")]
    address_type: Option<AddressType>,
    #[serde(rename = "isPrivkey")]
    is_privkey: bool,
    #[serde(rename = "isTestnet")]
    is_testnet: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum AddressType {
    #[serde(rename = "pubkey")]
    Pubkey,
    #[serde(rename = "script")]
    Script,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct InvalidKey(String);
