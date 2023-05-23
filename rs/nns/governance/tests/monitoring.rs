use crate::fake::FakeDriver;
use ic_nns_governance::{
    encode_metrics,
    governance::Governance,
    pb::v1::{Governance as GovernanceProto, RewardEvent},
};

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod fake;

#[test]
fn test_reward_event_amounts_metrics() {
    let governance_proto = GovernanceProto {
        latest_reward_event: Some(RewardEvent {
            total_available_e8s_equivalent: 100,
            ..Default::default()
        }),
        ..Default::default()
    };

    let helpers = FakeDriver::default();

    let governance = Governance::new(
        governance_proto,
        helpers.get_fake_env(),
        helpers.get_fake_ledger(),
        helpers.get_fake_cmc(),
    );

    let now = 123_456_789;
    let mut metrics_encoder = ic_metrics_encoder::MetricsEncoder::new(vec![], now);
    encode_metrics(&governance, &mut metrics_encoder).unwrap();
    let out = metrics_encoder.into_inner();
    let out = String::from_utf8(out).unwrap();

    assert!(out.len() > 1000, "{}", out.len());

    assert!(
        out.contains("governance_latest_reward_event_total_available_e8s 100"),
        "out.len() = {}",
        out.len(),
    );
}
