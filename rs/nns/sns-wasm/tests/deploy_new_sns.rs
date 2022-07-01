use candid::{Decode, Encode};
use canister_test::{Canister, Project, Runtime};
use dfn_core::bytes;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_crypto_sha::Sha256;
use ic_ic00_types::CanisterStatusResultV2;
use ic_ic00_types::CanisterStatusType::Running;
use ic_interfaces::registry::RegistryClient;
use ic_nns_test_utils::itest_helpers::{local_test_on_nns_subnet, set_up_sns_wasm_canister};
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::make_subnet_list_record_key;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, DeployNewSnsRequest, DeployNewSnsResponse, SnsCanisterIds, SnsCanisterType,
    SnsWasm,
};
use ic_test_utilities::types::ids::canister_test_id;
use registry_canister::mutations::common::decode_registry_value;
use std::convert::TryFrom;

#[test]
fn test_canisters_are_created_and_installed() {
    // Keeping a test on ReplicaTests for performance comparison
    local_test_on_nns_subnet(|runtime| async move {
        let fake_registry_client = match runtime {
            Runtime::Remote(_) => {
                panic!("Cannot run this test on Runtime::Remote at this time");
            }
            Runtime::Local(ref r) => r.registry_client.clone(),
        };

        let subnet_list_record = decode_registry_value::<SubnetListRecord>(
            fake_registry_client
                .get_value(
                    &make_subnet_list_record_key(),
                    fake_registry_client.get_latest_version(),
                )
                .unwrap()
                .unwrap(),
        );
        let system_subnet_id = SubnetId::new(
            PrincipalId::try_from(subnet_list_record.subnets.get(0).unwrap()).unwrap(),
        );

        let canister = set_up_sns_wasm_canister(
            &runtime,
            SnsWasmCanisterInitPayload {
                sns_subnet_ids: vec![system_subnet_id],
            },
        )
        .await;

        let root_wasm =
            Project::cargo_bin_maybe_use_path_relative_to_rs("sns/root", "sns-root-canister", &[]);
        let root_hash = Sha256::hash(&root_wasm.clone().bytes()).to_vec();
        canister
            .update_(
                "add_wasm",
                bytes,
                Encode!(&AddWasmRequest {
                    wasm: Some(SnsWasm {
                        wasm: root_wasm.clone().bytes(),
                        canister_type: SnsCanisterType::Root.into()
                    }),
                    hash: root_hash.clone()
                })
                .unwrap(),
            )
            .await
            .unwrap();

        let governance_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "sns/governance",
            "sns-governance-canister",
            &[],
        );
        let governance_hash = Sha256::hash(&governance_wasm.clone().bytes()).to_vec();
        canister
            .update_(
                "add_wasm",
                bytes,
                Encode!(&AddWasmRequest {
                    wasm: Some(SnsWasm {
                        wasm: governance_wasm.clone().bytes(),
                        canister_type: SnsCanisterType::Governance.into()
                    }),
                    hash: governance_hash.clone()
                })
                .unwrap(),
            )
            .await
            .unwrap();

        let ledger_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "rosetta-api/ledger_canister",
            "ledger-canister",
            &[],
        );
        let ledger_hash = Sha256::hash(&ledger_wasm.clone().bytes()).to_vec();
        canister
            .update_(
                "add_wasm",
                bytes,
                Encode!(&AddWasmRequest {
                    wasm: Some(SnsWasm {
                        wasm: ledger_wasm.clone().bytes(),
                        canister_type: SnsCanisterType::Ledger.into()
                    }),
                    hash: ledger_hash.clone()
                })
                .unwrap(),
            )
            .await
            .unwrap();

        let result = canister
            .update_(
                "deploy_new_sns",
                bytes,
                Encode!(&DeployNewSnsRequest {
                    sns_init_payload: Some(SnsInitPayload::with_valid_values_for_testing())
                })
                .unwrap(),
            )
            .await
            .unwrap();

        let response = Decode!(&result, DeployNewSnsResponse).unwrap();

        let root_canister_id = canister_test_id(1);
        let governance_canister_id = canister_test_id(2);
        let ledger_canister_id = canister_test_id(3);
        let swap_canister_id = canister_test_id(4);

        assert_eq!(
            response,
            DeployNewSnsResponse {
                subnet_id: Some(system_subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    governance: Some(governance_canister_id.get()),
                    root: Some(root_canister_id.get()),
                    ledger: Some(ledger_canister_id.get()),
                    swap: Some(swap_canister_id.get())
                })
            }
        );

        let root_canister_principal = response.canisters.unwrap().root.unwrap();
        let mut root_canister =
            Canister::new(&runtime, CanisterId::new(root_canister_principal).unwrap());
        root_canister.set_wasm(root_wasm.bytes());

        let principals: Vec<PrincipalId> = Vec::new();
        let result = root_canister
            .update_(
                "get_sns_canisters_summary",
                bytes,
                Encode!(&principals).unwrap(),
            )
            .await
            .unwrap();

        // We know from a successful response that the init_payload is in fact sent correctly
        // through CanisterApiImpl::install_wasm, since governance has to know root canister_id
        // in order to respond to root's request for its own status from governance
        // more detailed coverage of the initialization parameters is done through unit tests
        let mut response =
            Decode!(&result, Vec<(String, PrincipalId, CanisterStatusResultV2)>).unwrap();

        let root_tuple = response.remove(0);
        let governance_tuple = response.remove(0);
        let ledger_tuple = response.remove(0);

        // Assert that the canisters are installed in the same configuration that our response
        // told us above and controllers and installed wasms are correct
        assert_eq!(root_tuple.0, "root");
        assert_eq!(root_tuple.1, root_canister_id.get());
        assert_eq!(root_tuple.2.status(), Running);
        assert_eq!(root_tuple.2.controller(), governance_canister_id.get());
        assert_eq!(root_tuple.2.module_hash().unwrap(), root_hash);

        assert_eq!(governance_tuple.0, "governance");
        assert_eq!(governance_tuple.1, governance_canister_id.get());
        assert_eq!(governance_tuple.2.status(), Running);
        assert_eq!(governance_tuple.2.controller(), root_canister_id.get());
        assert_eq!(governance_tuple.2.module_hash().unwrap(), governance_hash);

        assert_eq!(ledger_tuple.0, "ledger");
        assert_eq!(ledger_tuple.1, ledger_canister_id.get());
        assert_eq!(ledger_tuple.2.status(), Running);
        assert_eq!(ledger_tuple.2.controller(), root_canister_id.get());
        assert_eq!(ledger_tuple.2.module_hash().unwrap(), ledger_hash);

        Ok(())
    });
}
