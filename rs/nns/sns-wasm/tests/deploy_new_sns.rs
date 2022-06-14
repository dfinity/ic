use candid::{Decode, Encode};
use canister_test::Runtime;
use dfn_core::bytes;
use ic_base_types::{PrincipalId, SubnetId};
use ic_interfaces::registry::RegistryClient;
use ic_nns_test_utils::itest_helpers::{local_test_on_nns_subnet, set_up_sns_wasm_canister};
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::make_subnet_list_record_key;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_sns_wasm::pb::v1::{DeployNewSns, DeployNewSnsResponse, SnsCanisterIds};
use ic_test_utilities::types::ids::canister_test_id;
use registry_canister::mutations::common::decode_registry_value;
use std::convert::TryFrom;

#[test]
fn test_canisters_are_created() {
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

        let payload = DeployNewSns {};

        let result = canister
            .update_("deploy_new_sns", bytes, Encode!(&payload).unwrap())
            .await
            .unwrap();

        let response = Decode!(&result, DeployNewSnsResponse).unwrap();

        assert_eq!(
            response,
            DeployNewSnsResponse {
                subnet_id: Some(system_subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    governance: Some(canister_test_id(1).get()),
                    root: Some(canister_test_id(2).get()),
                    ledger: Some(canister_test_id(3).get())
                })
            }
        );

        Ok(())
    });
}
