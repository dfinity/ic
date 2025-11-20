use crate::test_utils::MockRandomness;
use crate::{
    governance::Governance,
    node_provider_rewards::DateRangeFilter,
    pb::v1::MonthlyNodeProviderRewards,
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use std::sync::Arc;

#[test]
fn test_node_provider_rewards_read_from_correct_sources() {
    let rewards_1 = MonthlyNodeProviderRewards {
        timestamp: 1,
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
        start_date: None,
        end_date: None,
        algorithm_version: None,
    };

    let rewards_2 = MonthlyNodeProviderRewards {
        timestamp: 2,
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
        start_date: None,
        end_date: None,
        algorithm_version: None,
    };
    let mut governance = Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(vec![], 100)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    governance
        .heap_data
        .most_recent_monthly_node_provider_rewards = Some(rewards_1.clone());

    let result_1 = governance.get_most_recent_monthly_node_provider_rewards();

    assert_eq!(result_1.unwrap(), rewards_1);

    governance.update_most_recent_monthly_node_provider_rewards(rewards_2.clone());
    // TODO stop recording this in heap data
    assert_eq!(
        governance
            .heap_data
            .most_recent_monthly_node_provider_rewards,
        Some(rewards_2.clone())
    );

    let result_2 = governance.get_most_recent_monthly_node_provider_rewards();
    assert_eq!(result_2.unwrap(), rewards_2);
}

#[test]
fn test_list_node_provider_rewards_api() {
    let rewards_1 = MonthlyNodeProviderRewards {
        timestamp: 1721029451, // july 15 2024
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
        start_date: None,
        end_date: None,
        algorithm_version: None,
    };

    let rewards_2 = MonthlyNodeProviderRewards {
        timestamp: 1723707851, // august 15 2024
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
        start_date: None,
        end_date: None,
        algorithm_version: None,
    };

    let mut governance = Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(vec![], 100)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    governance.update_most_recent_monthly_node_provider_rewards(rewards_1.clone());

    governance.update_most_recent_monthly_node_provider_rewards(rewards_2.clone());

    let rewards = governance.list_node_provider_rewards(None);

    assert_eq!(rewards, vec![rewards_2, rewards_1]);
}

#[test]
fn test_list_node_provider_rewards_api_with_paging_and_filters() {
    let mut governance = Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(vec![], 100)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    let mut rewards_minted = vec![];

    for i in 1..=25 {
        let rewards = MonthlyNodeProviderRewards {
            timestamp: 100 * i, // july 15 2024
            rewards: vec![],
            xdr_conversion_rate: None,
            minimum_xdr_permyriad_per_icp: None,
            maximum_node_provider_rewards_e8s: None,
            registry_version: None,
            node_providers: vec![],
            start_date: None,
            end_date: None,
            algorithm_version: None,
        };
        governance.update_most_recent_monthly_node_provider_rewards(rewards.clone());
        rewards_minted.push(rewards);
    }

    let rewards = governance.list_node_provider_rewards(Some(DateRangeFilter {
        start: None,
        end: Some(rewards_minted[23].timestamp),
    }));

    // limit of 5
    assert_eq!(rewards.len(), 24);
    assert_eq!(
        rewards,
        rewards_minted[..=23]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
    );

    let rewards = governance.list_node_provider_rewards(None);
    assert_eq!(rewards.len(), 24);
    assert_eq!(
        rewards,
        rewards_minted[1..=24]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
    );
}
