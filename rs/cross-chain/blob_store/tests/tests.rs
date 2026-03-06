use blob_store_lib::api::{BlobMetadata, GetError, InsertError, InsertRequest};
use candid::{Decode, Encode, Principal};
use pocket_ic::PocketIc;

mod insert {
    use crate::{Setup, assert_eq_ignoring_timestamp, sha256_hex};
    use blob_store_lib::api::{BlobMetadata, InsertError};
    use candid::Principal;

    #[test]
    fn should_insert_once() {
        let setup = Setup::default();
        let blob_store = setup.blob_store();

        let data = b"hello".to_vec();
        let hash = sha256_hex(&data);

        let result = blob_store.insert(Setup::CONTROLLER, &hash, data.clone());
        assert_eq!(result, Ok(hash.clone()));

        let metadata = blob_store
            .get_metadata(Setup::CONTROLLER, &hash)
            .expect("metadata should exist after insert");
        assert_eq!(metadata.uploader, Setup::CONTROLLER);
        assert_eq!(metadata.size, data.len() as u64);
        assert!(metadata.inserted_at_ns > 0);
        assert!(metadata.tags.is_empty());

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
            Err(InsertError::InvalidHash { .. })
        ));
    }

    #[test]
    fn should_insert_with_tags() {
        let setup = Setup::default();
        let blob_store = setup.blob_store();
        let data = b"tagged-blob".to_vec();
        let size = data.len() as u64;
        let hash = sha256_hex(&data);
        let tags = vec!["beta".to_string(), "alpha".to_string()];
        let result = blob_store.insert_with_tags(Setup::CONTROLLER, &hash, data, Some(tags));
        assert_eq!(result, Ok(hash.clone()));

        let metadata = blob_store.get_metadata(Setup::CONTROLLER, &hash).unwrap();

        assert_eq_ignoring_timestamp(
            &metadata,
            &BlobMetadata {
                uploader: Setup::CONTROLLER,
                size,
                tags: vec!["alpha".to_string(), "beta".to_string()],
                inserted_at_ns: 0,
            },
        );
    }
}

mod get {
    use crate::{Setup, assert_eq_ignoring_timestamp, sha256_hex};
    use assert_matches::assert_matches;
    use blob_store_lib::api::{BlobMetadata, GetError};
    use candid::Principal;

    #[test]
    fn should_get_stored_data() {
        let setup = Setup::default();
        let blob_store = setup.blob_store();
        let data = b"hello".to_vec();
        let hash = sha256_hex(&data);
        assert_eq!(
            blob_store.insert(Setup::CONTROLLER, &hash, data.clone()),
            Ok(hash.clone())
        );

        for principal in [Principal::anonymous(), Setup::CONTROLLER] {
            assert_eq!(blob_store.get(principal, &hash), Ok(data.clone()));
            assert_eq_ignoring_timestamp(
                &blob_store
                    .get_metadata(principal, &hash)
                    .expect("metadata should exist"),
                &BlobMetadata {
                    uploader: Setup::CONTROLLER,
                    size: data.len() as u64,
                    inserted_at_ns: 0,
                    tags: Default::default(),
                },
            );

            assert_eq!(
                blob_store.get(principal, &sha256_hex(b"not-stored")),
                Err(GetError::NotFound)
            );
            assert_eq!(
                blob_store.get_metadata(principal, &sha256_hex(b"not-stored")),
                Err(GetError::NotFound)
            );

            assert_matches!(
                blob_store.get(principal, "not-a-hex-hash"),
                Err(GetError::InvalidHash { .. })
            );
            assert_matches!(
                blob_store.get_metadata(principal, "not-a-hex-hash"),
                Err(GetError::InvalidHash { .. })
            );
        }
    }
}

mod upgrade {
    use crate::{Setup, sha256_hex};
    use candid::Principal;

    #[test]
    fn should_preserve_data_after_upgrade() {
        let setup = Setup::default();
        let blob_store = setup.blob_store();

        let data = b"hello".to_vec();
        let hash = sha256_hex(&data);
        assert_eq!(
            blob_store.insert(Setup::CONTROLLER, &hash, data.clone()),
            Ok(hash.clone())
        );
        assert_eq!(
            blob_store.get(Principal::anonymous(), &hash),
            Ok(data.clone())
        );
        let metadata = blob_store
            .get_metadata(Principal::anonymous(), &hash)
            .expect("metadata should exist before upgrade");

        setup.upgrade();

        assert_eq!(blob_store.get(Principal::anonymous(), &hash), Ok(data));
        assert_eq!(
            blob_store.get_metadata(Principal::anonymous(), &hash),
            Ok(metadata)
        );
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

    pub fn upgrade(&self) {
        self.env
            .upgrade_canister(
                self.canister_id,
                blob_store_wasm(),
                Encode!(&()).unwrap(),
                Some(Self::CONTROLLER),
            )
            .expect("upgrade failed");
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
        self.insert_with_tags(sender, hash, data, None)
    }

    pub fn insert_with_tags(
        &self,
        sender: Principal,
        hash: &str,
        data: Vec<u8>,
        tags: Option<Vec<String>>,
    ) -> Result<String, InsertError> {
        let request = InsertRequest {
            hash: hash.to_string(),
            data,
            tags,
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

    pub fn get(&self, sender: Principal, hash: &str) -> Result<Vec<u8>, GetError> {
        let result = self
            .env
            .query_call(self.canister_id, sender, "get", Encode!(&hash).unwrap())
            .expect("query call failed");
        Decode!(&result, Result<Vec<u8>, GetError>).unwrap()
    }

    pub fn get_metadata(&self, sender: Principal, hash: &str) -> Result<BlobMetadata, GetError> {
        let result = self
            .env
            .query_call(
                self.canister_id,
                sender,
                "get_metadata",
                Encode!(&hash).unwrap(),
            )
            .expect("query call failed");
        Decode!(&result, Result<BlobMetadata, GetError>).unwrap()
    }
}

fn assert_eq_ignoring_timestamp(expected: &BlobMetadata, actual: &BlobMetadata) {
    let BlobMetadata {
        uploader: expected_uploader,
        size: expected_size,
        tags: expected_tags,
        inserted_at_ns: _,
    } = expected;
    let BlobMetadata {
        uploader: actual_uploader,
        size: actual_size,
        tags: actual_tags,
        inserted_at_ns: _,
    } = actual;
    assert_eq!(expected_uploader, actual_uploader);
    assert_eq!(expected_size, actual_size);
    assert_eq!(expected_tags, actual_tags);
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash: [u8; 32] = sha2::Sha256::digest(data).into();
    hex::encode(hash)
}
