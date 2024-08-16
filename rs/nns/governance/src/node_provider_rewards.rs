use crate::{
    pb::v1::{
        archived_monthly_node_provider_rewards, ArchivedMonthlyNodeProviderRewards,
        MonthlyNodeProviderRewards,
    },
    storage::with_node_provider_rewards_log,
};
use ic_stable_structures::{Memory, Storable};

pub(crate) fn record_node_provider_rewards(most_recent_rewards: MonthlyNodeProviderRewards) {
    let rewards = ArchivedMonthlyNodeProviderRewards {
        version: Some(archived_monthly_node_provider_rewards::Version::Version1(
            archived_monthly_node_provider_rewards::V1 {
                rewards: Some(most_recent_rewards),
            },
        )),
    };

    with_node_provider_rewards_log(|log| {
        log.append(&rewards).expect("TODO: panic message");
    })
}

pub(crate) fn latest_node_provider_rewards() -> Option<ArchivedMonthlyNodeProviderRewards> {
    with_node_provider_rewards_log(|log| {
        let len = log.len();
        if len == 0 {
            return None;
        }
        log.get(len - 1)
    })
}

pub(crate) fn list_node_provider_rewards(
    limit: u64,
    page: Option<u32>,
) -> Vec<ArchivedMonthlyNodeProviderRewards> {
    let page = page.unwrap_or(0);

    // If we have 10 entries, they're 0..9
    // If we are getting newest first, we want to return 9..4, then 4..0

    with_node_provider_rewards_log(|log| {
        let len = log.len();
        let end_range = len.saturating_sub(page as u64 * limit);
        let start_range = end_range.saturating_sub(limit);

        (start_range..end_range)
            .rev()
            .flat_map(|index| log.get(index))
            .collect()
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pb::v1::MonthlyNodeProviderRewards;

    #[test]
    fn test_record_and_read_rewards() {
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

        // Assert empty on start
        let latest = latest_node_provider_rewards();
        assert_eq!(latest, None);

        record_node_provider_rewards(rewards_1.clone());

        let latest = latest_node_provider_rewards().unwrap();

        assert_eq!(
            latest.version,
            Some(archived_monthly_node_provider_rewards::Version::Version1(
                archived_monthly_node_provider_rewards::V1 {
                    rewards: Some(rewards_1),
                },
            ))
        );

        record_node_provider_rewards(rewards_2.clone());

        let latest = latest_node_provider_rewards().unwrap();

        assert_eq!(
            latest.version,
            Some(archived_monthly_node_provider_rewards::Version::Version1(
                archived_monthly_node_provider_rewards::V1 {
                    rewards: Some(rewards_2),
                },
            ))
        );
    }
}
