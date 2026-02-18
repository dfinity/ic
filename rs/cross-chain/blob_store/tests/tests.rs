use blob_store_lib::api::{InsertError, InsertRequest};
use candid::{Decode, Encode, Principal};
use pocket_ic::PocketIc;

mod insert {
    use crate::{Setup, sha256_hex};
    use blob_store_lib::api::InsertError;
    use candid::Principal;

    #[test]
    fn should_insert_once() {
        let setup = Setup::default();
        let blob_store = setup.blob_store();

        let data = b"hello".to_vec();
        let hash = sha256_hex(&data);

        let result = blob_store.insert(Setup::CONTROLLER, &hash, data.clone());
        assert_eq!(result, Ok(hash.clone()));

        let result = blob_store.insert(Setup::CONTROLLER, &hash, data);
        assert_eq!(result, Err(InsertError::AlreadyExists));
    }

    #[test]
    fn should_not_insert() {
        let setup = Setup::default();
        let blob_store = setup.blob_store();
        let data = b"hello".to_vec();
        let hash = sha256_hex(&data);

        assert_eq!(
            blob_store.insert(Principal::anonymous(), &hash, data.clone()),
            Err(InsertError::NotAuthorized)
        );

        let wrong_hash = sha256_hex(b"wrong");
        assert_eq!(
            blob_store.insert(Setup::CONTROLLER, &wrong_hash, data.clone()),
            Err(InsertError::HashMismatch {
                expected: wrong_hash,
                actual: hash
            })
        );

        assert!(matches!(
            blob_store.insert(Setup::CONTROLLER, "not-a-hex-hash", data),
            Err(InsertError::InvalidHash(_))
        ));
    }
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
    pub fn insert(
        &self,
        sender: Principal,
        hash: &str,
        data: Vec<u8>,
    ) -> Result<String, InsertError> {
        let request = InsertRequest {
            hash: hash.to_string(),
            data,
        };
        let result = self
            .env
            .update_call(
                self.canister_id,
                sender,
                "insert",
                Encode!(&request).unwrap(),
            )
            .expect("update call failed");
        Decode!(&result, Result<String, InsertError>).unwrap()
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash: [u8; 32] = sha2::Sha256::digest(data).into();
    hex::encode(hash)
}
