pub mod pb;

use crate::pb::v1::{RegisterDappCanisterRequest, RegisterDappCanisterResponse, SnsRootCanister};
use async_trait::async_trait;
use dfn_core::api::call;
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_ic00_types::{CanisterIdRecord, CanisterStatusResultV2};
use std::{cell::RefCell, thread::LocalKey};

#[derive(Debug)]
pub struct CanisterCallError {
    pub code: Option<i32>,
    pub description: String,
}

impl From<(Option<i32>, String)> for CanisterCallError {
    fn from((code, description): (Option<i32>, String)) -> Self {
        Self { code, description }
    }
}

/// The managment (virtual) canister, also known as IC_00.
/// Reference: https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister
#[async_trait]
pub trait ManagementCanisterClient {
    async fn canister_status(
        &mut self,
        canister_id_record: &CanisterIdRecord,
    ) -> Result<CanisterStatusResultV2, CanisterCallError>;
}

// Defined in Rust instead of PB, because we want CanisterStatusResultV2
// (defined in ic00_types) to be in the response, but CSRV2 doesn't have a
// corresponding PB definition.
#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub struct GetSnsCanistersSummaryRequest {
    // This struct intentionally left blank (for now).
}

#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub struct GetSnsCanistersSummaryResponse {
    root_canister_summary: Option<CanisterSummary>,
    governance_canister_summary: Option<CanisterSummary>,
    ledger_canister_summary: Option<CanisterSummary>,
    dapp_canister_summaries: Vec<CanisterSummary>,
}

impl GetSnsCanistersSummaryResponse {
    pub fn root_canister_summary(&self) -> &CanisterSummary {
        self.root_canister_summary.as_ref().unwrap()
    }
    pub fn governance_canister_summary(&self) -> &CanisterSummary {
        self.governance_canister_summary.as_ref().unwrap()
    }
    pub fn ledger_canister_summary(&self) -> &CanisterSummary {
        self.ledger_canister_summary.as_ref().unwrap()
    }
    pub fn dapp_canister_summaries(&self) -> &Vec<CanisterSummary> {
        &self.dapp_canister_summaries
    }
}

#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub struct CanisterSummary {
    canister_id: Option<PrincipalId>,
    status: Option<CanisterStatusResultV2>,
}

impl CanisterSummary {
    pub fn canister_id(&self) -> PrincipalId {
        self.canister_id.unwrap()
    }
    pub fn status(&self) -> &CanisterStatusResultV2 {
        self.status.as_ref().unwrap()
    }
}

impl SnsRootCanister {
    fn governance_canister_id(&self) -> PrincipalId {
        self.governance_canister_id
            .expect("Invalid root canister state: missing governance_canister_id.")
    }

    fn ledger_canister_id(&self) -> PrincipalId {
        self.ledger_canister_id
            .expect("Invalid root canister state: missing ledger_canister_id.")
    }

    /// Return the canister status of all SNS canisters that this root canister
    /// is part of, as well as of all registered dapp canisters (See
    /// SnsRootCanister::register_dapp_canister).
    pub async fn get_sns_canisters_summary(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &mut impl ManagementCanisterClient,
        own_canister_id: CanisterId,
    ) -> GetSnsCanistersSummaryResponse {
        // Get ID of other canisters.
        let (governance_canister_id, ledger_canister_id, dapp_canister_ids) =
            self_ref.with(|self_ref| {
                let self_ref = self_ref.borrow();
                (
                    self_ref.governance_canister_id(),
                    self_ref.ledger_canister_id(),
                    self_ref.dapp_canister_ids.clone(),
                )
            });

        // Get our status.
        let root_status = get_root_status(governance_canister_id).await;
        let root_canister_summary = Some(CanisterSummary {
            canister_id: Some(own_canister_id.into()),
            status: Some(root_status),
        });

        // Get governance status.
        let governance_status = management_canister_client
            .canister_status(&CanisterIdRecord::from(
                CanisterId::try_from(governance_canister_id).expect(
                    "Could not convert from the recorded principal ID of the SNS \
                     governance to a canister ID.",
                ),
            ))
            .await
            .expect("Unable to get the status of the SNS governance canister.");
        let governance_canister_summary = Some(CanisterSummary {
            canister_id: Some(governance_canister_id),
            status: Some(governance_status),
        });

        // Get status of ledger.
        let ledger_status = management_canister_client
            .canister_status(&CanisterIdRecord::from(
                CanisterId::try_from(ledger_canister_id).expect(
                    "Could not convert from the recorded principal ID of the SNS \
                     ledger to a canister ID.",
                ),
            ))
            .await
            .expect("Unable to get the status of the SNS ledger canister.");
        let ledger_canister_summary = Some(CanisterSummary {
            canister_id: Some(ledger_canister_id),
            status: Some(ledger_status),
        });

        // Get status of dapp canister(s).
        let mut dapp_canister_summaries = vec![];
        for dapp_canister_id in dapp_canister_ids {
            let dapp_status = management_canister_client
                .canister_status(&CanisterIdRecord::from(
                    CanisterId::try_from(dapp_canister_id).unwrap_or_else(|e| {
                        panic!(
                            "Could not convert from the recorded principal ID of (one of) the \
                         Dapp's canisters ({dapp_canister_id}) to a canister ID: {e:#?}"
                        )
                    }),
                ))
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Unable to get the status of one of the Dapp's canisters \
                     ({dapp_canister_id}): {e:#?}"
                    )
                });
            dapp_canister_summaries.push(CanisterSummary {
                canister_id: Some(dapp_canister_id),
                status: Some(dapp_status),
            });
        }

        GetSnsCanistersSummaryResponse {
            root_canister_summary,
            governance_canister_summary,
            ledger_canister_summary,
            dapp_canister_summaries: vec![],
        }
    }

    /// Tells this canister (SNS root) about a dapp canister that it controls.
    ///
    /// The canister must not be one of the distinguished SNS canisters
    /// (i.e. root, governance, ledger). Furthermore, the canister must be
    /// exclusively be controlled by this canister (i.e. SNS root). Otherwise,
    /// the request will be rejected.
    ///
    /// Registered dapp canisters are used by at least two methods:
    ///   1. get_sns_canisters_summary
    ///   2. set_dapp_controllers (currently in review).
    pub async fn register_dapp_canister(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &mut impl ManagementCanisterClient,
        own_canister_id: CanisterId,
        request: RegisterDappCanisterRequest,
    ) -> RegisterDappCanisterResponse {
        // Validate/unpack request.
        let query_canister_id = request
            .canister_id
            .expect("Invalid RegisterDappCanisterRequest: canister_id field must be populated.");
        // Reject if canister_id is one of the distinguished canisters in the SNS.
        // TODO: Include ledger archive in this list: https://dfinity.atlassian.net/browse/NNS1-1488
        let sns_canister_ids = self_ref.with(|s| {
            let s = s.borrow();
            [
                s.governance_canister_id.unwrap(),
                s.ledger_canister_id.unwrap(),
                own_canister_id.into(),
            ]
        });
        if sns_canister_ids.contains(&query_canister_id) {
            panic!(
                "Invalid RegisterDappCanisterRequest: \
                 The requested canister is an SNS canister."
            );
        }
        let query_canister_id = CanisterId::new(query_canister_id)
            .expect("Invalid RegisterDappCanisterRequest: contained an invalid canister ID.");

        // Make sure we are a controller by querying the management canister.
        //
        // TODO: Add support for notifying that we have lost control of a
        // canister. Currently, only adding is supported, because that's the
        // only thing we need right now.
        let canister_status = management_canister_client
            .canister_status(&query_canister_id.into())
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "Unable to get the status of the canister referenced in the request: {err:#?}"
                )
            });
        // Reject if we do not have exclusive control.
        assert_eq!(
            canister_status.controllers(),
            vec![own_canister_id.into()],
            "The canister referenced by the request ({query_canister_id}) is not \
             exclusively controlled by this SNS root canister.",
        );

        // Add query_canister_id to self.dapp_canister_ids (if it isn't already there).
        self_ref.with(|s| {
            let query_canister_id = PrincipalId::from(query_canister_id);
            let mut s = s.borrow_mut();
            if s.dapp_canister_ids.contains(&query_canister_id) {
                return;
            }
            s.dapp_canister_ids.push(query_canister_id);
        });

        // Report success.
        RegisterDappCanisterResponse {}
    }
}

/// Get the canister status of the Root canister controlled by the given Governance canister.
/// Root cannot get its own status because only the controller of a canister is able to
/// query the canister's status, and Root is solely controlled by Governance.
async fn get_root_status(governance_id: PrincipalId) -> CanisterStatusResultV2 {
    call(
        CanisterId::new(governance_id).unwrap(),
        "get_root_canister_status",
        dfn_candid::candid,
        (),
    )
    .await
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::NumBytes;
    use ic_ic00_types::CanisterStatusType;

    #[derive(Debug)]
    struct CanisterStatusCall {
        expected_canister_id: PrincipalId,
        result: Result<CanisterStatusResultV2, CanisterCallError>,
    }

    #[derive(Debug)]
    struct MockManagementCanisterClient {
        calls: Vec<CanisterStatusCall>,
    }

    #[async_trait]
    impl ManagementCanisterClient for MockManagementCanisterClient {
        async fn canister_status(
            &mut self,
            observed_canister_id_record: &CanisterIdRecord,
        ) -> Result<CanisterStatusResultV2, CanisterCallError> {
            let CanisterStatusCall {
                expected_canister_id,
                result,
            } = self.calls.pop().unwrap();
            let observed_canister_id = observed_canister_id_record.get_canister_id();

            assert_eq!(
                PrincipalId::from(observed_canister_id),
                expected_canister_id
            );

            result
        }
    }

    impl Drop for MockManagementCanisterClient {
        fn drop(&mut self) {
            assert!(self.calls.is_empty(), "{self:#?}");
        }
    }

    #[tokio::test]
    async fn register_dapp_canister_happy() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                dapp_canister_ids: vec![],
            });
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);
        let dapp_canister_id = PrincipalId::new_user_test_id(4);

        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![CanisterStatusCall {
                expected_canister_id: dapp_canister_id,
                result: Ok(CanisterStatusResultV2::new(
                    CanisterStatusType::Running,
                    None,                       // module_hash
                    sns_root_canister_id,       // controller
                    vec![sns_root_canister_id], // controllers
                    NumBytes::new(42),          // memory_size
                    43,                         // cycles
                    44,                         // compute_allocation
                    None,                       // memory_allocation
                    45,                         // freezing_threshold
                    46,                         // idle_cycles_burned_per_day
                )),
            }],
        };

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canister(
            &SNS_ROOT_CANISTER,
            &mut management_canister_client,
            sns_root_canister_id.try_into().unwrap(),
            RegisterDappCanisterRequest {
                canister_id: Some(dapp_canister_id),
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanisterResponse {}, "{result:#?}");
        assert_eq!(
            management_canister_client.calls.len(),
            0,
            "{management_canister_client:#?}"
        );
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(
                *r.borrow(),
                SnsRootCanister {
                    // Most importantly, root became aware that it controls the
                    // dapp, since that is the whole point of calling notify_*,
                    // the code under test.
                    dapp_canister_ids: vec![dapp_canister_id],
                    ..original_sns_root_canister
                }
            );
        });
    }

    #[should_panic]
    #[tokio::test]
    async fn register_dapp_canister_sad() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                dapp_canister_ids: vec![],
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);
        let dapp_canister_id = PrincipalId::new_user_test_id(4);

        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![CanisterStatusCall {
                expected_canister_id: dapp_canister_id,
                result: Err(CanisterCallError {
                    code: None,
                    description: "You don't control that canister.".to_string(),
                }),
            }],
        };

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canister(
            &SNS_ROOT_CANISTER,
            &mut management_canister_client,
            sns_root_canister_id.try_into().unwrap(),
            RegisterDappCanisterRequest {
                canister_id: Some(dapp_canister_id),
            },
        )
        .await;

        // Step 3: Inspect results.
        eprintln!(
            "Should have panicked: {result:#?}, {:#?}",
            SNS_ROOT_CANISTER.with(|c| c.clone())
        );
    }

    #[tokio::test]
    async fn register_dapp_canister_redundant() {
        // Step 1: Prepare the world.
        thread_local! {
            static DAPP_CANISTER_ID: PrincipalId = PrincipalId::new_user_test_id(4);
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                dapp_canister_ids: vec![DAPP_CANISTER_ID.with(|i| *i)],
            });
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);

        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![CanisterStatusCall {
                expected_canister_id: DAPP_CANISTER_ID.with(|i| *i),
                result: Ok(CanisterStatusResultV2::new(
                    CanisterStatusType::Running,
                    None,                       // module_hash
                    sns_root_canister_id,       // controller
                    vec![sns_root_canister_id], // controllers
                    NumBytes::new(42),          // memory_size
                    43,                         // cycles
                    44,                         // compute_allocation
                    None,                       // memory_allocation
                    45,                         // freezing_threshold
                    46,                         // idle_cycles_burned_per_day
                )),
            }],
        };

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canister(
            &SNS_ROOT_CANISTER,
            &mut management_canister_client,
            sns_root_canister_id.try_into().unwrap(),
            RegisterDappCanisterRequest {
                canister_id: Some(DAPP_CANISTER_ID.with(|i| *i)),
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanisterResponse {}, "{result:#?}");
        assert_eq!(
            management_canister_client.calls.len(),
            0,
            "{management_canister_client:#?}"
        );
        // Assert no change (because we already knew about the dapp).
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(*r.borrow(), original_sns_root_canister);
        });
    }

    #[should_panic(expected = "exclusive")]
    #[tokio::test]
    async fn register_dapp_canister_not_exclusively_controlled() {
        // Step 1: Prepare the world.
        thread_local! {
            static DAPP_CANISTER_ID: PrincipalId = PrincipalId::new_user_test_id(4);
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                dapp_canister_ids: vec![DAPP_CANISTER_ID.with(|i| *i)],
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);

        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![CanisterStatusCall {
                expected_canister_id: DAPP_CANISTER_ID.with(|i| *i),
                result: Ok(CanisterStatusResultV2::new(
                    CanisterStatusType::Running,
                    None,                 // module_hash
                    sns_root_canister_id, // controller
                    // Controllers. This is the foil of this test:
                    vec![sns_root_canister_id, PrincipalId::new_user_test_id(9999)],
                    NumBytes::new(42), // memory_size
                    43,                // cycles
                    44,                // compute_allocation
                    None,              // memory_allocation
                    45,                // freezing_threshold
                    46,                // idle_cycles_burned_per_day
                )),
            }],
        };

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canister(
            &SNS_ROOT_CANISTER,
            &mut management_canister_client,
            sns_root_canister_id.try_into().unwrap(),
            RegisterDappCanisterRequest {
                canister_id: Some(DAPP_CANISTER_ID.with(|i| *i)),
            },
        )
        .await;

        // Step 3: Inspect results.
        // This is already mostly taken care of by #[should_panic].
        println!("Panic was not triggered! result: {result:#?}");
    }
}
