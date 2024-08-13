use crate::{
    governance::Governance,
    pb::v1::{Governance as GovernanceProto, MonthlyNodeProviderRewards},
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};

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
    };

    let rewards_2 = MonthlyNodeProviderRewards {
        timestamp: 2,
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
    };

    let mut governance = Governance::new(
        GovernanceProto {
            most_recent_monthly_node_provider_rewards: Some(rewards_1.clone()),
            ..Default::default()
        },
        Box::new(MockEnvironment::new(vec![], 100)),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

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
fn test_list_minted_node_provider_rewards_api() {
    let rewards_1 = MonthlyNodeProviderRewards {
        timestamp: 1721029451, // july 15 2024
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
    };

    let rewards_2 = MonthlyNodeProviderRewards {
        timestamp: 1723707851, // august 15 2024
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
    };

    let mut governance = Governance::new(
        GovernanceProto {
            ..Default::default()
        },
        Box::new(MockEnvironment::new(vec![], 100)),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    governance.update_most_recent_monthly_node_provider_rewards(rewards_1.clone());

    governance.update_most_recent_monthly_node_provider_rewards(rewards_2.clone());

    let result = governance.list_node_provider_rewards();

    assert_eq!(result, vec![rewards_1, rewards_2]);
}

#[test]
fn test_list_minted_node_provider_rewards_api_with_paging_and_filters() {
    let rewards_1 = MonthlyNodeProviderRewards {
        timestamp: 1721029451, // july 15 2024
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
    };

    let rewards_2 = MonthlyNodeProviderRewards {
        timestamp: 1723707851, // august 15 2024
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
    };
    let rewards_3 = MonthlyNodeProviderRewards {
        timestamp: 1726374659, // sept 15 2024
        rewards: vec![],
        xdr_conversion_rate: None,
        minimum_xdr_permyriad_per_icp: None,
        maximum_node_provider_rewards_e8s: None,
        registry_version: None,
        node_providers: vec![],
    };

    let mut governance = Governance::new(
        GovernanceProto {
            ..Default::default()
        },
        Box::new(MockEnvironment::new(vec![], 100)),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    governance.update_most_recent_monthly_node_provider_rewards(rewards_1.clone());

    governance.update_most_recent_monthly_node_provider_rewards(rewards_2.clone());

    governance.update_most_recent_monthly_node_provider_rewards(rewards_3.clone());

    let result = governance.list_node_provider_rewards(limit, filter);

    assert_eq!(result, vec![rewards_1, rewards_2]);
}
