use candid::{Encode, Nat};
use dfn_candid::candid;

use ic_nns_constants::{REGISTRY_CANISTER_ID, ROOT_CANISTER_ID};

use ic_nervous_system_root::{
    AddCanisterProposal, CanisterIdRecord, CanisterStatusResult, CanisterStatusType::Running,
};
use ic_nns_handler_root::init::RootCanisterInitPayloadBuilder;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_root_canister, set_up_universal_canister,
    },
    registry::get_value,
    registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_protobuf::registry::nns::v1::NnsCanisterRecords;
use ic_registry_keys::make_nns_canister_records_key;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

use ic_test_utilities::empty_wasm::{EMPTY_WASM, EMPTY_WASM_SHA256};

use ic_types::CanisterId;

use std::convert::TryFrom;

/// Tests that the root can add a canister.
#[test]
fn test_add_nns_canister() {
    local_test_on_nns_subnet(|runtime| async move {
        // Set up the registry first so that it gets its expected id.
        let init_payload = RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
            .build();
        let registry = set_up_registry_canister(&runtime, init_payload).await;
        assert_eq!(registry.canister_id(), REGISTRY_CANISTER_ID);

        // Install the universal canister in place of the governance canister so
        // it can impersonate it.
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let _fake_ledger = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .unwrap();

        let root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;
        assert_eq!(root.canister_id(), ROOT_CANISTER_ID);

        let name = "i dunno, what would be a good canister name?".to_string();

        let proposal = AddCanisterProposal {
            name: name.clone(),
            wasm_module: EMPTY_WASM.to_vec(),
            arg: vec![],
            query_allocation: Some(Nat::from(34)),
            memory_allocation: Some(Nat::from(12345)),
            compute_allocation: Some(Nat::from(12)),
            initial_cycles: 1 << 45,
            authz_changes: Vec::new(),
        };

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &root,
                "add_nns_canister",
                Encode!(&proposal).unwrap(),
            )
            .await
        );

        // The proposal execution to add an NNS canister only responds when everything
        // is done (as opposed to the one to upgrade a canister). So we don't need to
        // poll here: can directly assert that the execution is successful.

        let nns_canister_records: NnsCanisterRecords =
            get_value(&registry, make_nns_canister_records_key().as_bytes()).await;
        let new_canister_record = nns_canister_records.canisters.get(&name).unwrap();
        let new_canister_id =
            CanisterId::try_from(new_canister_record.id.clone().unwrap()).unwrap();

        let status: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(new_canister_id),),
            )
            .await
            .unwrap();
        assert_eq!(status.status, Running, "{:?}", status);
        assert_eq!(
            status.module_hash,
            Some(EMPTY_WASM_SHA256.to_vec()),
            "{:?}",
            status
        );
        assert_eq!(status.controller, root.canister_id().get(), "{:?}", status);

        Ok(())
    });
}
