use crate::canister_api::CanisterApi;
use crate::pb::hash_to_hex_string;
use crate::pb::v1::add_wasm_response::{AddWasmError, AddWasmOk};
use crate::pb::v1::{
    add_wasm_response, AddWasm, AddWasmResponse, DeployNewSns, DeployNewSnsResponse, DeployedSns,
    GetWasm, GetWasmResponse, ListDeployedSnses, ListDeployedSnsesResponse, SnsCanisterIds,
    SnsCanisterType, SnsWasm,
};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_types::{Cycles, SubnetId};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::thread::LocalKey;

/// The struct that implements the public API of the canister
#[derive(Default)]
pub struct SnsWasmCanister {
    /// Internal store for wasms
    wasm_storage: SnsWasmStorage,
    /// Allowed subnets for SNS's to be installed
    sns_subnet_ids: Vec<SubnetId>,
    /// Stored deployed_sns instances
    deployed_sns_list: Vec<DeployedSns>,
}

impl SnsWasmCanister {
    pub fn new() -> Self {
        SnsWasmCanister::default()
    }

    pub fn set_sns_subnets(&mut self, subnet_ids: Vec<SubnetId>) {
        self.sns_subnet_ids = subnet_ids;
    }

    /// Returns an Option(SnsWasm) in the GetWasmResponse (a struct with wasm bytecode and the install target)
    pub fn get_wasm(&self, get_wasm_payload: GetWasm) -> GetWasmResponse {
        let hash = vec_to_hash(get_wasm_payload.hash);
        GetWasmResponse {
            wasm: self.wasm_storage.get_wasm(&hash).cloned(),
        }
    }

    /// Adds a WASM to the canister's storage, validating that the expected hash matches that of the
    /// provided WASM bytecode.
    pub fn add_wasm(&mut self, add_wasm_payload: AddWasm) -> AddWasmResponse {
        let wasm = add_wasm_payload.wasm.expect("Wasm is required");
        let hash = vec_to_hash(add_wasm_payload.hash);

        let result = match self.wasm_storage.add_wasm(wasm, &hash) {
            Ok(_) => Some(add_wasm_response::Result::Ok(AddWasmOk {
                hash: hash.to_vec(),
            })),
            Err(msg) => Some(add_wasm_response::Result::Error(AddWasmError {
                error: msg,
            })),
        };
        AddWasmResponse { result }
    }

    /// Returns a list of Deployed SNS root CanisterId's and the subnet they were deployed to.
    pub fn list_deployed_snses(
        &self,
        _list_sns_payload: ListDeployedSnses,
    ) -> ListDeployedSnsesResponse {
        ListDeployedSnsesResponse {
            instances: self.deployed_sns_list.clone(),
        }
    }

    /// Deploys a new SNS based on the parameters of the payload
    pub async fn deploy_new_sns(
        thread_safe_sns: &'static LocalKey<RefCell<SnsWasmCanister>>,
        canister_api: &impl CanisterApi,
        _deploy_new_sns_payload: DeployNewSns,
    ) -> DeployNewSnsResponse {
        let subnet_id =
            thread_safe_sns.with(|sns_canister| sns_canister.borrow().get_available_sns_subnet());

        let canisters = Self::create_sns_canisters(canister_api, subnet_id).await;

        thread_safe_sns.with(|sns_canister| {
            sns_canister
                .borrow_mut()
                .deployed_sns_list
                .push(DeployedSns {
                    root_canister_id: canisters.root,
                })
        });

        DeployNewSnsResponse {
            subnet_id: Some(subnet_id.get()),
            canisters: Some(canisters),
        }
    }

    async fn create_sns_canisters(
        canister_api: &impl CanisterApi,
        subnet_id: SubnetId,
    ) -> SnsCanisterIds {
        // TODO error handling
        // TODO where do we get these cycles?
        let this_canister_id = canister_api.local_canister_id().get();
        let governance = canister_api
            .create_canister(subnet_id, this_canister_id, Cycles::new(1_000_000_000))
            .await
            .unwrap();
        let root = canister_api
            .create_canister(subnet_id, this_canister_id, Cycles::new(1_000_000_000))
            .await
            .unwrap();
        let ledger = canister_api
            .create_canister(subnet_id, this_canister_id, Cycles::new(1_000_000_000))
            .await
            .unwrap();

        SnsCanisterIds {
            governance: Some(governance.get()),
            root: Some(root.get()),
            ledger: Some(ledger.get()),
        }
    }

    pub fn get_available_sns_subnet(&self) -> SubnetId {
        // TODO something more sophisticated
        self.sns_subnet_ids[0]
    }
}

/// This struct is responsible for storing and retrieving the wasms held by the canister
#[derive(Default)]
pub struct SnsWasmStorage {
    /// Map of sha256 hashs of wasms to the WASM.  
    wasm_map: BTreeMap<[u8; 32], SnsWasm>,
}

/// Converts a vector to a sha256 hash, or panics if the vector is the wrong length
fn vec_to_hash(v: Vec<u8>) -> [u8; 32] {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; 32]> = match boxed_slice.try_into() {
        Ok(hash) => hash,
        Err(o) => panic!("Expected a hash of length {} but it was {}", 32, o.len()),
    };
    *boxed_array
}

impl SnsWasmStorage {
    pub fn new() -> Self {
        SnsWasmStorage::default()
    }

    /// Adds a wasm to the storage
    /// Validates that the expected hash matches the sha256 hash of the WASM.
    fn add_wasm(&mut self, wasm: SnsWasm, expected_hash: &[u8; 32]) -> Result<(), String> {
        if wasm.canister_type == i32::from(SnsCanisterType::Unspecified) {
            return Err("SnsWasm::canister_type cannot be 'Unspecified' (0).".to_string());
        }

        if !SnsCanisterType::is_valid(wasm.canister_type) {
            return Err(
                "Invalid value for SnsWasm::canister_type.  See documentation for valid values"
                    .to_string(),
            );
        }

        if expected_hash != &wasm.sha256_hash() {
            return Err(format!(
                "Invalid Sha256 given for submitted WASM bytes.  Provided hash was '{}'  but \
                calculated hash was '{}'",
                hash_to_hex_string(expected_hash),
                wasm.sha256_string()
            ));
        }

        self.wasm_map.insert(expected_hash.to_owned(), wasm);

        Ok(())
    }

    /// Retrieves a wasm by its hash.
    pub fn get_wasm(&self, hash: &[u8; 32]) -> Option<&SnsWasm> {
        self.wasm_map.get(hash)
    }
}

#[cfg(test)]
mod test {
    use crate::canister_api::CanisterApi;
    use crate::pb::hash_to_hex_string;
    use crate::pb::v1::{
        add_wasm_response,
        add_wasm_response::{AddWasmError, AddWasmOk},
        AddWasm, DeployNewSns, DeployNewSnsResponse, DeployedSns, GetWasm, ListDeployedSnses,
        ListDeployedSnsesResponse, SnsCanisterIds, SnsCanisterType,
    };
    use crate::sns_wasm::{SnsWasm, SnsWasmCanister, SnsWasmStorage};
    use async_trait::async_trait;
    use ic_crypto_sha::Sha256;
    use ic_test_utilities::types::ids::{canister_test_id, subnet_test_id};
    use ic_types::{CanisterId, Cycles, PrincipalId, SubnetId};
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct TestCanisterApi {
        canisters_created: Arc<Mutex<u64>>,
    }

    #[async_trait]
    impl CanisterApi for TestCanisterApi {
        fn local_canister_id(&self) -> CanisterId {
            canister_test_id(0)
        }

        async fn create_canister(
            &self,
            _target_subnet: SubnetId,
            _controller_id: PrincipalId,
            _cycles: Cycles,
        ) -> Result<CanisterId, String> {
            let mut data = self.canisters_created.lock().unwrap();
            *data += 1;
            let canister_id = canister_test_id(*data);
            Ok(canister_id)
        }
    }

    fn new_canister_api() -> TestCanisterApi {
        TestCanisterApi {
            canisters_created: Arc::new(Mutex::new(0)),
        }
    }

    /// Provides a small wasm
    fn smallest_valid_wasm() -> SnsWasm {
        SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: i32::from(SnsCanisterType::Governance),
        }
    }

    fn new_wasm_storage() -> SnsWasmStorage {
        SnsWasmStorage::new()
    }

    fn new_wasm_canister() -> SnsWasmCanister {
        SnsWasmCanister::new()
    }

    #[test]
    fn canister_can_store_wasm() {
        let mut canister = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);

        canister.add_wasm(wasm.clone(), &expected_hash).unwrap();

        let stored_wasm = canister.get_wasm(&expected_hash);

        assert_eq!(stored_wasm.unwrap(), &wasm);
    }

    #[test]
    fn storage_fails_on_invalid_wasm_hash() {
        let mut canister = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let invalid_hash = Sha256::hash("Something else".as_bytes());

        let result = canister.add_wasm(wasm.clone(), &invalid_hash);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Sha256 given for submitted WASM bytes.  Provided hash was \
            'CC72843144841A6F8110B7EBE7A1768101E03C4C8C152865CB7207E8E4BF8745'  but calculated \
            hash was '93A44BBB96C751218E4C00D479E4C14358122A389ACCA16205B1E4D0DC5F9476'"
        );
        // Assert that it is not stored
        let retrieved_wasm = canister.get_wasm(&wasm.sha256_hash());
        assert!(retrieved_wasm.is_none());
    }

    #[test]
    fn retrieval_fails_on_invalid_wasm_hash() {
        let mut canister = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);

        canister.add_wasm(wasm, &expected_hash).unwrap();

        let bad_hash = Sha256::hash("something_else".as_bytes());
        let stored_wasm = canister.get_wasm(&bad_hash);

        assert!(stored_wasm.is_none());
    }

    #[test]
    fn test_api_get_wasm_returns_right_response() {
        let mut canister = new_wasm_canister();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);
        canister.add_wasm(AddWasm {
            wasm: Some(wasm.clone()),
            hash: expected_hash.to_vec(),
        });

        let bad_hash = Sha256::hash("something_else".as_bytes());
        let wasm_response = canister.get_wasm(GetWasm {
            hash: bad_hash.to_vec(),
        });

        // When given non-existent hash, return None
        assert!(wasm_response.wasm.is_none());

        let wasm_response = canister.get_wasm(GetWasm {
            hash: expected_hash.to_vec(),
        });
        // When given valid hash return correct SnsWasm
        assert_eq!(wasm_response.wasm.unwrap(), wasm);
    }

    #[test]
    fn test_api_add_wasm_fails_on_unspecified_canister_type() {
        let mut canister = new_wasm_canister();
        let unspecified_canister_wasm = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: i32::from(SnsCanisterType::Unspecified),
        };

        let response = canister.add_wasm(AddWasm {
            wasm: Some(unspecified_canister_wasm.clone()),
            hash: unspecified_canister_wasm.sha256_hash().to_vec(),
        });

        assert_eq!(
            response.result.unwrap(),
            add_wasm_response::Result::Error(add_wasm_response::AddWasmError {
                error: "SnsWasm::canister_type cannot be 'Unspecified' (0).".to_string()
            })
        )
    }

    #[test]
    fn test_api_add_wasm_fails_on_unsupported_canister_type() {
        let mut canister = new_wasm_canister();
        let invalid_canister_type_wasm = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: 1000,
        };

        let response = canister.add_wasm(AddWasm {
            wasm: Some(invalid_canister_type_wasm.clone()),
            hash: invalid_canister_type_wasm.sha256_hash().to_vec(),
        });

        assert_eq!(
            response.result.unwrap(),
            add_wasm_response::Result::Error(add_wasm_response::AddWasmError {
                error:
                    "Invalid value for SnsWasm::canister_type.  See documentation for valid values"
                        .to_string()
            })
        )
    }

    #[test]
    fn test_api_add_wasm_responses() {
        let mut canister = new_wasm_canister();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);
        let bad_hash = Sha256::hash("Something else".as_bytes());
        // First try with incorrect hash
        let failure = canister.add_wasm(AddWasm {
            wasm: Some(wasm.clone()),
            hash: bad_hash.to_vec(),
        });
        assert_eq!(
            failure.result.unwrap(),
            add_wasm_response::Result::Error(AddWasmError {
                error: format!(
                    "Invalid Sha256 given for submitted WASM bytes.  Provided hash was \
                '{}'  but calculated hash was \
                '{}'",
                    hash_to_hex_string(&bad_hash),
                    hash_to_hex_string(&expected_hash),
                )
            })
        );

        let valid_hash = wasm.sha256_hash();
        let success = canister.add_wasm(AddWasm {
            wasm: Some(wasm),
            hash: valid_hash.to_vec(),
        });

        assert_eq!(
            success.result.unwrap(),
            add_wasm_response::Result::Ok(AddWasmOk {
                hash: valid_hash.to_vec()
            })
        );
    }

    #[tokio::test]
    async fn test_deploy_new_sns_to_subnet_creates_canisters() {
        let test_id = subnet_test_id(1);
        thread_local! {
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister> = RefCell::new(new_wasm_canister()) ;
        }

        CANISTER_WRAPPER.with(|c| {
            c.borrow_mut().set_sns_subnets(vec![test_id]);
        });

        let response = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &new_canister_api(),
            DeployNewSns {},
        )
        .await;

        assert_eq!(
            response,
            DeployNewSnsResponse {
                subnet_id: Some(test_id.get()),
                canisters: Some(SnsCanisterIds {
                    governance: Some(canister_test_id(1).get()),
                    root: Some(canister_test_id(2).get()),
                    ledger: Some(canister_test_id(3).get())
                })
            }
        );
    }

    #[tokio::test]
    async fn test_deploy_new_sns_records_root_canisters() {
        let test_id = subnet_test_id(1);
        let canister_api = new_canister_api();
        thread_local! {
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister> = RefCell::new(new_wasm_canister()) ;
        }

        CANISTER_WRAPPER.with(|c| {
            c.borrow_mut().set_sns_subnets(vec![test_id]);
        });

        let root_canister_1 =
            SnsWasmCanister::deploy_new_sns(&CANISTER_WRAPPER, &canister_api, DeployNewSns {})
                .await
                .canisters
                .unwrap()
                .root
                .unwrap();

        let root_canister_2 =
            SnsWasmCanister::deploy_new_sns(&CANISTER_WRAPPER, &canister_api, DeployNewSns {})
                .await
                .canisters
                .unwrap()
                .root
                .unwrap();

        assert_ne!(root_canister_1, root_canister_2);

        let known_deployments_response = CANISTER_WRAPPER
            .with(|canister| canister.borrow().list_deployed_snses(ListDeployedSnses {}));

        assert_eq!(
            known_deployments_response,
            ListDeployedSnsesResponse {
                instances: vec![
                    DeployedSns {
                        root_canister_id: Some(root_canister_1),
                    },
                    DeployedSns {
                        root_canister_id: Some(root_canister_2),
                    },
                ],
            },
        )
    }
}
