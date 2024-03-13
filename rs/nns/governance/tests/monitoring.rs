use crate::fake::FakeDriver;
use ic_nns_governance::{
    encode_metrics, governance::Governance, governance_proto_builder::GovernanceProtoBuilder,
    pb::v1::RewardEvent,
};

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod fake;

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod common;

#[test]
fn test_reward_event_amounts_metrics() {
    let governance_proto = GovernanceProtoBuilder::new()
        .with_latest_reward_event(RewardEvent {
            total_available_e8s_equivalent: 100,
            ..Default::default()
        })
        .build();

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
