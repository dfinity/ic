use candid::{CandidType, Decode, Encode, Principal};
use pocket_ic::PocketIc;
use serde::Deserialize;

#[test]
fn test_greet() {
    let setup = Setup::default();
    let blob_store = setup.blob_store();

    let greeting = blob_store.greet("World");

    assert_eq!(greeting, "Hello, World!");
}

#[test]
fn test_record_success() {
    let setup = Setup::default();
    let blob_store = setup.blob_store();

    let data = b"hello".to_vec();
    let hash = sha256_hex(&data);

    let result = blob_store.record(Setup::CONTROLLER, &hash, data);

    assert_eq!(result, Ok(hash));
}

#[test]
fn test_record_not_authorized() {
    let setup = Setup::default();
    let blob_store = setup.blob_store();

    let data = b"hello".to_vec();
    let hash = sha256_hex(&data);

    let result = blob_store.record(Principal::anonymous(), &hash, data);

    assert_eq!(result, Err(RecordError::NotAuthorized));
}

#[test]
fn test_record_already_exists() {
    let setup = Setup::default();
    let blob_store = setup.blob_store();

    let data = b"hello".to_vec();
    let hash = sha256_hex(&data);
    blob_store
        .record(Setup::CONTROLLER, &hash, data.clone())
        .expect("first record should succeed");

    let result = blob_store.record(Setup::CONTROLLER, &hash, data);

    assert_eq!(result, Err(RecordError::AlreadyExists));
}

#[test]
fn test_record_hash_mismatch() {
    let setup = Setup::default();
    let blob_store = setup.blob_store();

    let data = b"hello".to_vec();
    let wrong_hash = sha256_hex(b"wrong");

    let result = blob_store.record(Setup::CONTROLLER, &wrong_hash, data);

    assert!(matches!(result, Err(RecordError::HashMismatch { .. })));
}

#[test]
fn test_record_invalid_hash() {
    let setup = Setup::default();
    let blob_store = setup.blob_store();

    let result = blob_store.record(Setup::CONTROLLER, "not-a-hex-hash", b"hello".to_vec());

    assert!(matches!(result, Err(RecordError::InvalidHash(_))));
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash: [u8; 32] = sha2::Sha256::digest(data).into();
    hex::encode(hash)
}

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct RecordRequest {
    pub hash: String,
    pub data: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub enum RecordError {
    NotAuthorized,
    InvalidHash(String),
    HashMismatch { expected: String, actual: String },
    AlreadyExists,
}

pub struct Setup {
    pub env: PocketIc,
    pub canister_id: Principal,
}

impl Setup {
    pub const CONTROLLER: Principal = Principal::from_slice(&[0_u8, 1, 2]);

    pub fn new() -> Self {
        let env = PocketIc::new();
        let canister_id = env.create_canister_with_settings(Some(Self::CONTROLLER), None);
        env.add_cycles(canister_id, 3_000_000_000_000);
        env.install_canister(
            canister_id,
            blob_store_wasm(),
            Encode!(&()).unwrap(),
            Some(Self::CONTROLLER),
        );
        Self { env, canister_id }
    }

    pub fn blob_store(&self) -> BlobStoreCanister<'_> {
        BlobStoreCanister {
            env: &self.env,
            canister_id: self.canister_id,
        }
    }
}

impl Default for Setup {
    fn default() -> Self {
        Self::new()
    }
}

fn blob_store_wasm() -> Vec<u8> {
    let wasm_path =
        std::env::var("BLOB_STORE_CANISTER_WASM_PATH").expect("missing wasm path env var");
    std::fs::read(wasm_path).expect("failed to read canister wasm")
}

pub struct BlobStoreCanister<'a> {
    env: &'a PocketIc,
    canister_id: Principal,
}

impl<'a> BlobStoreCanister<'a> {
    pub fn greet(&self, name: &str) -> String {
        let result = self
            .env
            .query_call(
                self.canister_id,
                Principal::anonymous(),
                "greet",
                Encode!(&name).unwrap(),
            )
            .expect("query call failed");
        Decode!(&result, String).unwrap()
    }

    pub fn record(
        &self,
        sender: Principal,
        hash: &str,
        data: Vec<u8>,
    ) -> Result<String, RecordError> {
        let request = RecordRequest {
            hash: hash.to_string(),
            data,
        };
        let result = self
            .env
            .update_call(
                self.canister_id,
                sender,
                "record",
                Encode!(&request).unwrap(),
            )
            .expect("update call failed");
        Decode!(&result, Result<String, RecordError>).unwrap()
    }
}
