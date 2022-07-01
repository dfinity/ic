use crate::canister_api::CanisterApi;
use crate::pb::hash_to_hex_string;
use crate::pb::v1::add_wasm_response::{AddWasmError, AddWasmOk};
use crate::pb::v1::{
    add_wasm_response, AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
    DeployedSns, GetNextSnsVersionRequest, GetNextSnsVersionResponse, GetWasmRequest,
    GetWasmResponse, ListDeployedSnsesRequest, ListDeployedSnsesResponse, SnsCanisterIds,
    SnsCanisterType, SnsVersion, SnsWasm,
};
use candid::Encode;
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::CanisterId;
use ic_sns_init::SnsCanisterInitPayloads;
use ic_types::{Cycles, SubnetId};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
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
    /// Specifies the upgrade path for SNS instances
    upgrade_path: UpgradePath,
}

/// Internal implementation to give the wasms we explicitly handle a name (instead of Vec<u8>) for
/// safer handling in our internal logic.  This is not intended to be persisted outside of method logic
struct SnsWasms {
    root: Vec<u8>,
    governance: Vec<u8>,
    ledger: Vec<u8>,
}

impl SnsWasms {
    fn new(version: &SnsVersion, storage: &SnsWasmStorage) -> Self {
        let root = storage
            .get_wasm(&vec_to_hash(version.root_wasm_hash.clone()))
            .expect("No root wasm with that hash found")
            .clone()
            .wasm;
        let governance = storage
            .get_wasm(&vec_to_hash(version.governance_wasm_hash.clone()))
            .expect("No governance wasm found with that hash")
            .clone()
            .wasm;
        let ledger = storage
            .get_wasm(&vec_to_hash(version.ledger_wasm_hash.clone()))
            .expect("No ledger wasm found with that hash")
            .clone()
            .wasm;

        Self {
            root,
            governance,
            ledger,
        }
    }
}

impl SnsWasmCanister {
    pub fn new() -> Self {
        SnsWasmCanister::default()
    }

    pub fn set_sns_subnets(&mut self, subnet_ids: Vec<SubnetId>) {
        self.sns_subnet_ids = subnet_ids;
    }

    /// Returns an Option(SnsWasm) in the GetWasmResponse (a struct with wasm bytecode and the install target)
    pub fn get_wasm(&self, get_wasm_payload: GetWasmRequest) -> GetWasmResponse {
        let hash = vec_to_hash(get_wasm_payload.hash);
        GetWasmResponse {
            wasm: self.wasm_storage.get_wasm(&hash).cloned(),
        }
    }

    /// Adds a WASM to the canister's storage, validating that the expected hash matches that of the
    /// provided WASM bytecode.
    pub fn add_wasm(&mut self, add_wasm_payload: AddWasmRequest) -> AddWasmResponse {
        let wasm = add_wasm_payload.wasm.expect("Wasm is required");
        let sns_canister_type = wasm.checked_sns_canister_type();
        let hash = vec_to_hash(add_wasm_payload.hash);

        let result = match self.wasm_storage.add_wasm(wasm, &hash) {
            Ok(_) => {
                self.upgrade_path
                    .add_wasm(sns_canister_type.expect("Invalid canister_type"), &hash);

                Some(add_wasm_response::Result::Ok(AddWasmOk {
                    hash: hash.to_vec(),
                }))
            }
            Err(msg) => Some(add_wasm_response::Result::Error(AddWasmError {
                error: msg,
            })),
        };

        AddWasmResponse { result }
    }

    /// Returns a list of Deployed SNS root CanisterId's and the subnet they were deployed to.
    pub fn list_deployed_snses(
        &self,
        _list_sns_payload: ListDeployedSnsesRequest,
    ) -> ListDeployedSnsesResponse {
        ListDeployedSnsesResponse {
            instances: self.deployed_sns_list.clone(),
        }
    }

    /// Deploys a new SNS based on the parameters of the payload
    pub async fn deploy_new_sns(
        thread_safe_sns: &'static LocalKey<RefCell<SnsWasmCanister>>,
        canister_api: &impl CanisterApi,
        deploy_new_sns_payload: DeployNewSnsRequest,
    ) -> DeployNewSnsResponse {
        let subnet_id =
            thread_safe_sns.with(|sns_canister| sns_canister.borrow().get_available_sns_subnet());

        // TODO(NNS1-1437) Refund cycles if this step fails
        // TODO(NNS1-1437) Delete these canisters if any step fails
        let canisters = Self::create_sns_canisters(canister_api, subnet_id).await;

        let initial_payloads = deploy_new_sns_payload
            .sns_init_payload
            .unwrap()
            .validate()
            .unwrap()
            .build_canister_payloads(&canisters.clone().try_into().unwrap())
            .unwrap();

        let latest_wasms =
            thread_safe_sns.with(|sns_wasms| sns_wasms.borrow().get_latest_version_wasms());

        // TODO(NNS1-1437) Refund cycles if this step fails
        Self::install_wasms(canister_api, &canisters, latest_wasms, initial_payloads).await;

        // TODO(NNS1-1437) Refund cycles if this step fails
        Self::set_controllers(canister_api, &canisters).await;

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

    /// Sets the controllers of the SNS canisters so that Root controls Governance + Ledger, and
    /// Governance controls Root
    async fn set_controllers(canister_api: &impl CanisterApi, canisters: &SnsCanisterIds) {
        // Set Root as controller of Ledger and Governance.
        canister_api
            .set_controller(
                CanisterId::new(canisters.governance.unwrap()).unwrap(),
                canisters.root.unwrap(),
            )
            .await
            .expect("Unable to set Root as Governance canister controller.");
        canister_api
            .set_controller(
                CanisterId::new(canisters.ledger.unwrap()).unwrap(),
                canisters.root.unwrap(),
            )
            .await
            .expect("Unable to set Root as Ledger canister controller.");
        // Set Governance as controller of Root.
        canister_api
            .set_controller(
                CanisterId::new(canisters.root.unwrap()).unwrap(),
                canisters.governance.unwrap(),
            )
            .await
            .expect("Unable to set Governance as Root canister controller.");
    }

    /// Install the SNS Wasms onto the canisters with the specified payloads
    async fn install_wasms(
        canister_api: &impl CanisterApi,
        canisters: &SnsCanisterIds,
        latest_wasms: SnsWasms,
        init_payloads: SnsCanisterInitPayloads,
    ) {
        let mut results = futures::future::join_all(vec![
            canister_api.install_wasm(
                CanisterId::new(canisters.root.unwrap()).unwrap(),
                latest_wasms.root,
                Encode!(&init_payloads.root).unwrap(),
            ),
            canister_api.install_wasm(
                CanisterId::new(canisters.governance.unwrap()).unwrap(),
                latest_wasms.governance,
                Encode!(&init_payloads.governance).unwrap(),
            ),
            canister_api.install_wasm(
                CanisterId::new(canisters.ledger.unwrap()).unwrap(),
                latest_wasms.ledger,
                Encode!(&init_payloads.ledger).unwrap(),
            ),
        ])
        .await;

        results.remove(0).expect("Could not install Root WASM");
        results
            .remove(0)
            .expect("Could not install Governance WASM");
        results.remove(0).expect("Could not install Ledger WASM");
    }

    /// Create the Canisters for the SNS to be deployed
    async fn create_sns_canisters(
        canister_api: &impl CanisterApi,
        subnet_id: SubnetId,
    ) -> SnsCanisterIds {
        // TODO(NNS1-1437) How many cycles should each canister be allocated
        let this_canister_id = canister_api.local_canister_id().get();
        let root = canister_api
            .create_canister(subnet_id, this_canister_id, Cycles::new(1_000_000_000))
            .await
            .unwrap();

        let governance = canister_api
            .create_canister(subnet_id, this_canister_id, Cycles::new(1_000_000_000))
            .await
            .unwrap();

        let ledger = canister_api
            .create_canister(subnet_id, this_canister_id, Cycles::new(1_000_000_000))
            .await
            .unwrap();

        let swap = canister_api
            .create_canister(subnet_id, this_canister_id, Cycles::new(1_000_000_000))
            .await
            .unwrap();

        SnsCanisterIds {
            governance: Some(governance.get()),
            root: Some(root.get()),
            ledger: Some(ledger.get()),
            // TODO - do we always deploy with SWAP?
            swap: Some(swap.get()),
        }
    }

    /// Get an available subnet to create canisters on
    pub fn get_available_sns_subnet(&self) -> SubnetId {
        // TODO We need a way to find "available" subnets based on SNS deployments (limiting numbers per Subnet)
        self.sns_subnet_ids[0]
    }

    /// Given the SnsVersion of an SNS instance, returns the SnsVersion that this SNS instance
    /// should upgrade to
    pub fn get_next_sns_version(
        &self,
        request: GetNextSnsVersionRequest,
    ) -> GetNextSnsVersionResponse {
        let next_version = request
            .current_version
            .and_then(|sns_version| self.upgrade_path.upgrade_path.get(&sns_version).cloned());

        GetNextSnsVersionResponse { next_version }
    }

    /// Get the latest version of the WASMs based on the latest SnsVersion
    fn get_latest_version_wasms(&self) -> SnsWasms {
        SnsWasms::new(&self.upgrade_path.latest_version, &self.wasm_storage)
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
        // Validate the SnsCanisterType
        let _ = wasm.checked_sns_canister_type()?;

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

/// Specifies the upgrade path for SNS instances
#[derive(Default)]
pub struct UpgradePath {
    // The latest SNS version. New SNS deployments will deploy the SNS canisters specified by
    // this version.
    latest_version: SnsVersion,

    // Maps SnsVersions to the SnsVersion that should be upgraded to.
    upgrade_path: HashMap<SnsVersion, SnsVersion>,
}

impl UpgradePath {
    pub fn add_wasm(&mut self, canister_type: SnsCanisterType, wasm_hash: &[u8; 32]) {
        let mut new_latest_version = self.latest_version.clone();

        match canister_type {
            SnsCanisterType::Unspecified => panic!("SNS canister type must be non-zero"),
            SnsCanisterType::Root => new_latest_version.root_wasm_hash = wasm_hash.to_vec(),
            SnsCanisterType::Governance => {
                new_latest_version.governance_wasm_hash = wasm_hash.to_vec()
            }
            SnsCanisterType::Ledger => new_latest_version.ledger_wasm_hash = wasm_hash.to_vec(),
        }

        self.upgrade_path
            .insert(self.latest_version.clone(), new_latest_version.clone());
        self.latest_version = new_latest_version;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use async_trait::async_trait;
    use candid::{Decode, Encode};
    use ic_base_types::PrincipalId;
    use ic_crypto_sha::Sha256;
    use ic_sns_init::pb::v1::SnsInitPayload;
    use ic_test_utilities::types::ids::{canister_test_id, subnet_test_id};
    use ledger_canister::LedgerCanisterInitPayload;
    use std::sync::{Arc, Mutex};

    struct TestCanisterApi {
        canisters_created: Arc<Mutex<u64>>,
        // keep track of calls to our mocked methods
        #[allow(clippy::type_complexity)]
        pub install_wasm_calls: Arc<Mutex<Vec<(CanisterId, Vec<u8>, Vec<u8>)>>>,
        pub set_controller_calls: Arc<Mutex<Vec<(CanisterId, PrincipalId)>>>,
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

        async fn install_wasm(
            &self,
            target_canister: CanisterId,
            wasm: Vec<u8>,
            init_payload: Vec<u8>,
        ) -> Result<(), String> {
            self.install_wasm_calls
                .lock()
                .unwrap()
                .push((target_canister, wasm, init_payload));

            Ok(())
        }

        async fn set_controller(
            &self,
            canister: CanisterId,
            controller: PrincipalId,
        ) -> Result<(), String> {
            self.set_controller_calls
                .lock()
                .unwrap()
                .push((canister, controller));
            Ok(())
        }
    }

    fn new_canister_api() -> TestCanisterApi {
        TestCanisterApi {
            canisters_created: Arc::new(Mutex::new(0)),
            install_wasm_calls: Arc::new(Mutex::new(vec![])),
            set_controller_calls: Arc::new(Mutex::new(vec![])),
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

    /// Add some placeholder wasms with different values so we can test
    /// that each value is installed into the correct spot
    fn add_mock_wasms(canister: &mut SnsWasmCanister) {
        let root = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: i32::from(SnsCanisterType::Root),
        };
        let root_hash = root.sha256_hash();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(root),
            hash: root_hash.to_vec(),
        });
        let governance = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 1],
            canister_type: i32::from(SnsCanisterType::Governance),
        };
        let governance_hash = governance.sha256_hash();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(governance),
            hash: governance_hash.to_vec(),
        });
        let ledger = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 2],
            canister_type: i32::from(SnsCanisterType::Ledger),
        };
        let ledger_hash = ledger.sha256_hash();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(ledger),
            hash: ledger_hash.to_vec(),
        });
    }

    #[test]
    fn canister_can_store_wasm() {
        let mut storage = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);

        storage.add_wasm(wasm.clone(), &expected_hash).unwrap();

        let stored_wasm = storage.get_wasm(&expected_hash);

        assert_eq!(stored_wasm.unwrap(), &wasm);
    }

    #[test]
    fn storage_fails_on_invalid_wasm_hash() {
        let mut storage = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let invalid_hash = Sha256::hash("Something else".as_bytes());

        let result = storage.add_wasm(wasm.clone(), &invalid_hash);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Sha256 given for submitted WASM bytes.  Provided hash was \
            'CC72843144841A6F8110B7EBE7A1768101E03C4C8C152865CB7207E8E4BF8745'  but calculated \
            hash was '93A44BBB96C751218E4C00D479E4C14358122A389ACCA16205B1E4D0DC5F9476'"
        );
        // Assert that it is not stored
        let retrieved_wasm = storage.get_wasm(&wasm.sha256_hash());
        assert!(retrieved_wasm.is_none());
    }

    #[test]
    fn retrieval_fails_on_invalid_wasm_hash() {
        let mut storage = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);

        storage.add_wasm(wasm, &expected_hash).unwrap();

        let bad_hash = Sha256::hash("something_else".as_bytes());
        let stored_wasm = storage.get_wasm(&bad_hash);

        assert!(stored_wasm.is_none());
    }

    #[test]
    fn test_api_get_wasm_returns_right_response() {
        let mut canister = new_wasm_canister();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);
        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: expected_hash.to_vec(),
        });

        let bad_hash = Sha256::hash("something_else".as_bytes());
        let wasm_response = canister.get_wasm(GetWasmRequest {
            hash: bad_hash.to_vec(),
        });

        // When given non-existent hash, return None
        assert!(wasm_response.wasm.is_none());

        let wasm_response = canister.get_wasm(GetWasmRequest {
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

        let response = canister.add_wasm(AddWasmRequest {
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

        let response = canister.add_wasm(AddWasmRequest {
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
        let failure = canister.add_wasm(AddWasmRequest {
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
        let success = canister.add_wasm(AddWasmRequest {
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

    /// Adds Governance and Ledger WASMs and asserts that the upgrade path is updated by
    /// these calls to add_wasm
    #[test]
    fn test_add_wasm_updates_upgrade_path() {
        let mut canister = new_wasm_canister();

        assert_eq!(
            canister.get_next_sns_version(SnsVersion::default().into()),
            GetNextSnsVersionResponse::default()
        );

        let mut wasm = smallest_valid_wasm();

        // Add a Governance WASM
        wasm.canister_type = i32::from(SnsCanisterType::Governance);

        let valid_hash = wasm.sha256_hash();
        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: valid_hash.to_vec(),
        });

        // Add a Root WASM
        wasm.canister_type = i32::from(SnsCanisterType::Root);

        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm.clone()),
            hash: valid_hash.to_vec(),
        });

        // Add a Ledger WASM
        wasm.canister_type = i32::from(SnsCanisterType::Ledger);

        canister.add_wasm(AddWasmRequest {
            wasm: Some(wasm),
            hash: valid_hash.to_vec(),
        });

        // Assert that the upgrade path was constructed as expected
        let expected_next_sns_version1 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            ..Default::default()
        };

        let expected_next_sns_version2 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            root_wasm_hash: valid_hash.to_vec(),
            ..Default::default()
        };

        let expected_next_sns_version3 = SnsVersion {
            governance_wasm_hash: valid_hash.to_vec(),
            root_wasm_hash: valid_hash.to_vec(),
            ledger_wasm_hash: valid_hash.to_vec(),
        };

        assert_eq!(
            canister.get_next_sns_version(SnsVersion::default().into()),
            expected_next_sns_version1.clone().into()
        );

        assert_eq!(
            canister.get_next_sns_version(expected_next_sns_version1.into()),
            expected_next_sns_version2.clone().into()
        );

        assert_eq!(
            canister.get_next_sns_version(expected_next_sns_version2.into()),
            expected_next_sns_version3.into()
        );
    }

    #[tokio::test]
    async fn test_deploy_new_sns_to_subnet_creates_canisters_and_installs_with_correct_params() {
        thread_local! {
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister> = RefCell::new(new_wasm_canister()) ;
        }

        let test_id = subnet_test_id(1);
        CANISTER_WRAPPER.with(|c| {
            c.borrow_mut().set_sns_subnets(vec![test_id]);
            add_mock_wasms(&mut c.borrow_mut());
        });

        let init_payload = SnsInitPayload::with_valid_values_for_testing();
        let canister_api = new_canister_api();

        let response = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &canister_api,
            DeployNewSnsRequest {
                sns_init_payload: Some(init_payload.clone()),
            },
        )
        .await;

        let root_id = canister_test_id(1);
        let governance_id = canister_test_id(2);
        let ledger_id = canister_test_id(3);
        let swap_id = canister_test_id(4);

        assert_eq!(
            response,
            DeployNewSnsResponse {
                subnet_id: Some(test_id.get()),
                canisters: Some(SnsCanisterIds {
                    root: Some(root_id.get()),
                    governance: Some(governance_id.get()),
                    ledger: Some(ledger_id.get()),
                    swap: Some(swap_id.get())
                })
            }
        );

        let wasms_payloads = init_payload
            .validate()
            .unwrap()
            .build_canister_payloads(
                &SnsCanisterIds {
                    root: Some(root_id.get()),
                    governance: Some(governance_id.get()),
                    ledger: Some(ledger_id.get()),
                    swap: Some(swap_id.get()),
                }
                .try_into()
                .unwrap(),
            )
            .unwrap();

        // Now we assert that the expected canisters got the expected wasms with expected init params
        let SnsCanisterInitPayloads {
            root,
            governance,
            ledger,
            ..
        } = wasms_payloads;

        let root_args = canister_api.install_wasm_calls.lock().unwrap().remove(0);
        assert_eq!(
            root_args,
            (
                // root
                root_id,
                vec![0, 97, 115, 109, 1, 0, 0, 0],
                Encode!(&root).unwrap()
            )
        );

        let governance_args = canister_api.install_wasm_calls.lock().unwrap().remove(0);
        assert_eq!(
            governance_args,
            (
                // governance
                governance_id,
                vec![0, 97, 115, 109, 1, 0, 0, 1],
                Encode!(&governance).unwrap()
            )
        );
        // We actually Decode! here because LedgerCanisterInitPayload uses hashset and hashmap
        // which have non-deterministic ordering (and therefore serialization results)
        let (ledger_canister, ledger_wasm, ledger_init_args) =
            canister_api.install_wasm_calls.lock().unwrap().remove(0);
        assert_eq!(
            (
                ledger_canister,
                ledger_wasm,
                Decode!(&ledger_init_args, LedgerCanisterInitPayload).unwrap()
            ),
            (
                // ledger
                ledger_id,
                vec![0, 97, 115, 109, 1, 0, 0, 2],
                ledger
            )
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
            add_mock_wasms(&mut c.borrow_mut());
        });

        let root_canister_1 = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &canister_api,
            DeployNewSnsRequest {
                sns_init_payload: Some(SnsInitPayload::with_valid_values_for_testing()),
            },
        )
        .await
        .canisters
        .unwrap()
        .root
        .unwrap();

        let root_canister_2 = SnsWasmCanister::deploy_new_sns(
            &CANISTER_WRAPPER,
            &canister_api,
            DeployNewSnsRequest {
                sns_init_payload: Some(SnsInitPayload::with_valid_values_for_testing()),
            },
        )
        .await
        .canisters
        .unwrap()
        .root
        .unwrap();

        assert_ne!(root_canister_1, root_canister_2);

        let known_deployments_response = CANISTER_WRAPPER.with(|canister| {
            canister
                .borrow()
                .list_deployed_snses(ListDeployedSnsesRequest {})
        });

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
