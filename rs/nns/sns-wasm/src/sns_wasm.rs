use crate::canister_api::CanisterApi;
use crate::pb::hash_to_hex_string;
use crate::pb::v1::add_wasm_response::{AddWasmError, AddWasmOk};
use crate::pb::v1::{
    add_wasm_response, AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
    DeployedSns, GetNextSnsVersionRequest, GetNextSnsVersionResponse, GetWasmRequest,
    GetWasmResponse, ListDeployedSnsesRequest, ListDeployedSnsesResponse, SnsCanisterIds,
    SnsCanisterType, SnsVersion, SnsWasm, SnsWasmStableIndex, StableCanisterState,
};
use crate::stable_memory::SnsWasmStableMemory;
use candid::Encode;
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::CanisterId;
use ic_cdk::api::stable::StableMemory;
use ic_sns_init::SnsCanisterInitPayloads;
use ic_types::{Cycles, SubnetId};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::thread::LocalKey;

/// The struct that implements the public API of the canister
#[derive(Clone, Default)]
pub struct SnsWasmCanister<M: StableMemory + Clone + Default>
where
    SnsWasmCanister<M>: From<StableCanisterState>,
{
    /// A map from WASM hash to the index of this WASM in stable memory
    pub wasm_indexes: BTreeMap<[u8; 32], SnsWasmStableIndex>,
    /// Allowed subnets for SNS's to be installed
    pub sns_subnet_ids: Vec<SubnetId>,
    /// Stored deployed_sns instances
    pub deployed_sns_list: Vec<DeployedSns>,
    /// Specifies the upgrade path for SNS instances
    pub upgrade_path: UpgradePath,
    /// Provides convenient access to stable memory
    pub stable_memory: SnsWasmStableMemory<M>,
}

/// Internal implementation to give the wasms we explicitly handle a name (instead of Vec<u8>) for
/// safer handling in our internal logic.  This is not intended to be persisted outside of method logic
struct SnsWasms {
    root: Vec<u8>,
    governance: Vec<u8>,
    ledger: Vec<u8>,
}

impl<M: StableMemory + Clone + Default> SnsWasmCanister<M>
where
    SnsWasmCanister<M>: From<StableCanisterState>,
{
    pub fn new() -> Self {
        SnsWasmCanister::<M>::default()
    }

    pub fn set_sns_subnets(&mut self, subnet_ids: Vec<SubnetId>) {
        self.sns_subnet_ids = subnet_ids;
    }

    /// Initialize stable memory. Should only be called on canister init.
    pub fn initialize_stable_memory(&self) {
        self.stable_memory
            .init()
            .expect("Failed to initialize stable memory")
    }

    /// Returns an Option(SnsWasm) in the GetWasmResponse (a struct with wasm bytecode and the install target)
    pub fn get_wasm(&self, get_wasm_payload: GetWasmRequest) -> GetWasmResponse {
        let hash = vec_to_hash(get_wasm_payload.hash);
        GetWasmResponse {
            wasm: self.read_wasm(&hash),
        }
    }

    /// Read a WASM with the given hash from stable memory, if such a WASM exists
    fn read_wasm(&self, hash: &[u8; 32]) -> Option<SnsWasm> {
        self.wasm_indexes
            .get(hash)
            .and_then(|index| self.stable_memory.read_wasm(index.offset, index.size).ok())
    }

    /// Adds a WASM to the canister's storage, validating that the expected hash matches that of the
    /// provided WASM bytecode.
    pub fn add_wasm(&mut self, add_wasm_payload: AddWasmRequest) -> AddWasmResponse {
        let wasm = add_wasm_payload.wasm.expect("Wasm is required");

        let sns_canister_type = match wasm.checked_sns_canister_type() {
            Ok(canister_type) => canister_type,
            Err(error) => {
                return AddWasmResponse {
                    result: Some(add_wasm_response::Result::Error(AddWasmError { error })),
                }
            }
        };

        let hash = vec_to_hash(add_wasm_payload.hash);

        if hash != wasm.sha256_hash() {
            return AddWasmResponse {
                result: Some(add_wasm_response::Result::Error(AddWasmError {
                    error: format!("Invalid Sha256 given for submitted WASM bytes. Provided hash was '{}'  but calculated hash was '{}'",
                                   hash_to_hex_string(&hash), wasm.sha256_string())
                }))
            };
        }

        let result = match self.stable_memory.write_wasm(wasm) {
            Ok((offset, size)) => {
                self.wasm_indexes.insert(
                    hash,
                    SnsWasmStableIndex {
                        hash: hash.to_vec(),
                        offset,
                        size,
                    },
                );

                self.upgrade_path.add_wasm(sns_canister_type, &hash);

                Some(add_wasm_response::Result::Ok(AddWasmOk {
                    hash: hash.to_vec(),
                }))
            }
            Err(e) => Some(add_wasm_response::Result::Error(AddWasmError {
                error: format!("Unable to persist WASM: {}", e),
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
        thread_safe_sns: &'static LocalKey<RefCell<SnsWasmCanister<M>>>,
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
        let root_hash = self.upgrade_path.latest_version.root_wasm_hash.clone();
        let governance_hash = self
            .upgrade_path
            .latest_version
            .governance_wasm_hash
            .clone();
        let ledger_hash = self.upgrade_path.latest_version.ledger_wasm_hash.clone();

        let root = self
            .read_wasm(&vec_to_hash(root_hash))
            .expect("No root wasm with that hash found")
            .wasm;
        let governance = self
            .read_wasm(&vec_to_hash(governance_hash))
            .expect("No governance wasm found with that hash")
            .wasm;
        let ledger = self
            .read_wasm(&vec_to_hash(ledger_hash))
            .expect("No ledger wasm found with that hash")
            .wasm;

        SnsWasms {
            root,
            governance,
            ledger,
        }
    }

    /// Write canister state to stable memory
    pub fn write_state_to_stable_memory(&self) {
        self.stable_memory
            .write_canister_state(self.clone().into())
            .expect("Failed to write canister state from stable memory")
    }

    /// Read canister state from stable memory
    pub fn from_stable_memory() -> Self {
        SnsWasmStableMemory::<M>::default()
            .read_canister_state()
            .expect("Failed to read canister state from stable memory")
            .into()
    }
}

/// Converts a vector to a sha256 hash, or panics if the vector is the wrong length
pub fn vec_to_hash(v: Vec<u8>) -> [u8; 32] {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; 32]> = match boxed_slice.try_into() {
        Ok(hash) => hash,
        Err(o) => panic!("Expected a hash of length {} but it was {}", 32, o.len()),
    };
    *boxed_array
}

/// Specifies the upgrade path for SNS instances
#[derive(Clone, Default, Debug, candid::CandidType, candid::Deserialize, PartialEq)]
pub struct UpgradePath {
    /// The latest SNS version. New SNS deployments will deploy the SNS canisters specified by
    /// this version.
    pub latest_version: SnsVersion,

    /// Maps SnsVersions to the SnsVersion that should be upgraded to.
    pub upgrade_path: HashMap<SnsVersion, SnsVersion>,
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
    use crate::canister_stable_memory::TestCanisterStableMemory;
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

    fn new_wasm_canister() -> SnsWasmCanister<TestCanisterStableMemory> {
        let state = SnsWasmCanister::new();
        state.initialize_stable_memory();
        state
    }

    /// Add some placeholder wasms with different values so we can test
    /// that each value is installed into the correct spot
    fn add_mock_wasms(canister: &mut SnsWasmCanister<TestCanisterStableMemory>) {
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
                    "Invalid Sha256 given for submitted WASM bytes. Provided hash was \
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
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister<TestCanisterStableMemory>> = RefCell::new(new_wasm_canister()) ;
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
            static CANISTER_WRAPPER: RefCell<SnsWasmCanister<TestCanisterStableMemory>> = RefCell::new(new_wasm_canister()) ;
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
