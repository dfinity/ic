use async_trait::async_trait;
use candid::{Encode, Principal};
use ic_error_types::UserError;
use ic_nervous_system_agent::{pocketic_impl::PocketIcAgent, CallCanisters};
use ic_nervous_system_chunks::test_data::{MegaBlob, MEGA_BLOB_CONTENT};
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::common::{build_test_registry_wasm, NnsInitPayloadsBuilder};
use ic_registry_canister_api::mutate_test_high_capacity_records;
use ic_replay::player::{
    public_only_for_test_registry_get_value as registry_get_value, PerformQuery, PerformQueryResult,
};
use ic_types::{ingress::WasmResult, messages::Query, time::expiry_time_from_now, Time};
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};
use std::{convert::Infallible, time::SystemTime};
use strum::IntoEnumIterator;

struct PerformQueryImpl<'a> {
    pocket_ic: &'a PocketIc,
}

#[async_trait]
impl PerformQuery for PerformQueryImpl<'_> {
    async fn perform_query(&self, query: Query) -> Result<PerformQueryResult, Infallible> {
        let Query {
            receiver,
            method_name,
            method_payload,

            source: _ignored,
        } = query;

        let before_call_time = Time::try_from(SystemTime::now()).unwrap();

        // The real work happens here.
        let result = self
            .pocket_ic
            .query_call(
                Principal::from(receiver), // callee
                Principal::anonymous(),    // caller
                &method_name,
                method_payload,
            )
            .await;

        // The rest is just converting to the required return type.

        let result = match result {
            Ok(ok) => Ok(WasmResult::Reply(ok)),

            Err(err) => {
                // Convert error_code.
                let pocket_ic_error_code = err.error_code as i32;
                let mut code = ic_error_types::ErrorCode::UnknownManagementMessage;
                for ic_error_code in ic_error_types::ErrorCode::iter() {
                    if ic_error_code as i32 == pocket_ic_error_code {
                        code = ic_error_code;
                        break;
                    }
                }

                Err(UserError::new(code, format!("{:?}", err)))
            }
        };

        let result = (
            result,
            // Not sure if this is right. Indirection overload!
            before_call_time,
        );

        Ok(Ok(result))
    }
}

#[tokio::test]
async fn test_registry_get_value() {
    // Step 1: Prepare the world.

    // Step 1.1: Create a simulated ICP (to wit, PocketIc).
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    // Step 1.2: Install Registry canister on PocketIc.
    let mut nns_configuration = NnsInitPayloadsBuilder::new();
    let registry_init_args = nns_configuration
        .with_initial_invariant_compliant_mutations()
        .build()
        .registry;
    install_canister(
        &pocket_ic,
        "Registry",
        REGISTRY_CANISTER_ID,
        Encode!(&registry_init_args).unwrap(),
        build_test_registry_wasm(),
        Some(REGISTRY_CANISTER_ID.get()),
    )
    .await;

    // Step 1.3: Add large (chunked) record to the Registry canister.
    PocketIcAgent::new(&pocket_ic, GOVERNANCE_CANISTER_ID)
        .call(
            REGISTRY_CANISTER_ID,
            mutate_test_high_capacity_records::Request {
                id: 42,
                operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
            },
        )
        .await
        .unwrap();

    // Step 2: Call code under test.

    let perform_query = PerformQueryImpl {
        pocket_ic: &pocket_ic,
    };
    let observed_mega_blob: MegaBlob =
        registry_get_value(42, expiry_time_from_now(), &perform_query)
            .await
            .unwrap();

    // Step 3: Verify result(s).

    // assert_eq is intentionally not used here, because that would create lots of spam.
    assert!(
        observed_mega_blob
            == MegaBlob {
                content: MEGA_BLOB_CONTENT.clone()
            },
        "len={} vs. {}",
        observed_mega_blob.content.len(),
        MEGA_BLOB_CONTENT.len(),
    );
}
