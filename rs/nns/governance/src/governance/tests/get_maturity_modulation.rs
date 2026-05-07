use crate::governance::{
    Governance,
    tests::{MockEnvironment, StubCMC, StubIcpLedger},
};
use crate::pb::v1::MaturityModulation;
use crate::test_utils::MockRandomness;
use ic_nns_governance_api::{
    GetMaturityModulationResponse, MaturityModulation as ApiMaturityModulation,
};
use std::sync::Arc;

const SECONDS_PER_DAY: u64 = 86_400;

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
fn returns_none_when_unset() {
    let governance = make_governance();

    let response = governance.get_maturity_modulation();

    assert_eq!(
        response,
        GetMaturityModulationResponse {
            maturity_modulation: None
        }
    );
}

#[test]
fn converts_days_since_epoch_to_seconds() {
    let mut governance = make_governance();
    governance.heap_data.maturity_modulation = Some(MaturityModulation {
        current_value_permyriad: Some(123),
        updated_at_days_since_epoch: Some(20_000),
    });

    let response = governance.get_maturity_modulation();

    assert_eq!(
        response,
        GetMaturityModulationResponse {
            maturity_modulation: Some(ApiMaturityModulation {
                current_value_permyriad: Some(123),
                updated_at_timestamp_seconds: Some(20_000 * SECONDS_PER_DAY),
            }),
        }
    );
}
