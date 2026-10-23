use crate::governance::{
    Governance,
    tests::{MockEnvironment, StubCMC, StubIcpLedger},
};
use crate::pb::v1::MaturityModulation;
use crate::test_utils::MockRandomness;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nns_governance_api::{
    GetMaturityModulationResponse, MaturityModulation as ApiMaturityModulation,
};
use std::sync::Arc;

fn make_governance() -> Governance {
    Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(vec![], 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    )
}

#[test]
fn defaults_to_zero_at_init() {
    // `initialize_governance` seeds `heap_data.maturity_modulation` with a neutral 0-permyriad
    // value at init so spawning and disbursement keep working immediately rather than early-
    // returning while the XRC-fed price history task accumulates enough data to compute a real
    // value. `updated_at_days_since_epoch` is left at 0 (the "never measured" sentinel), which
    // the API conversion surfaces as `None`.
    let governance = make_governance();

    let response = governance.get_maturity_modulation();

    assert_eq!(
        response,
        GetMaturityModulationResponse {
            maturity_modulation: Some(ApiMaturityModulation {
                current_value_permyriad: Some(0),
                updated_at_timestamp_seconds: None,
            }),
        }
    );
}

#[test]
fn converts_days_since_epoch_to_seconds() {
    let mut governance = make_governance();
    governance.heap_data.maturity_modulation = Some(MaturityModulation {
        current_value_permyriad: 123,
        updated_at_days_since_epoch: 20_000,
    });

    let response = governance.get_maturity_modulation();

    assert_eq!(
        response,
        GetMaturityModulationResponse {
            maturity_modulation: Some(ApiMaturityModulation {
                current_value_permyriad: Some(123),
                updated_at_timestamp_seconds: Some(20_000 * ONE_DAY_SECONDS),
            }),
        }
    );
}

#[test]
fn updated_at_returns_none_when_days_overflow() {
    let mut governance = make_governance();
    governance.heap_data.maturity_modulation = Some(MaturityModulation {
        current_value_permyriad: 123,
        updated_at_days_since_epoch: u64::MAX,
    });

    let response = governance.get_maturity_modulation();

    assert_eq!(
        response,
        GetMaturityModulationResponse {
            maturity_modulation: Some(ApiMaturityModulation {
                current_value_permyriad: Some(123),
                updated_at_timestamp_seconds: None,
            }),
        }
    );
}
