use crate::{
    pb::v1::{
        archived_monthly_node_provider_rewards, archived_monthly_node_provider_rewards::Version,
        ArchivedMonthlyNodeProviderRewards, MonthlyNodeProviderRewards,
    },
    storage::with_node_provider_rewards_log,
};

// Filter type
#[derive(Default)]
pub struct DateRangeFilter {
    start: Option<u64>,
    end: Option<u64>,
}

// Conversion from API type
impl From<ic_nns_governance_api::pb::v1::DateRangeFilter> for DateRangeFilter {
    fn from(filter: ic_nns_governance_api::pb::v1::DateRangeFilter) -> Self {
        Self {
            start: filter.start_timestamp_seconds,
            end: filter.end_timestamp_seconds,
        }
    }
}

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
    date_filter: Option<DateRangeFilter>,
) -> (Option<u32>, Vec<ArchivedMonthlyNodeProviderRewards>) {
    let page = page.unwrap_or(0);

    let date_filter = date_filter.unwrap_or_default();
    let start_timestamp = date_filter.start.unwrap_or(0);
    let end_timestamp = date_filter.end.unwrap_or(u64::MAX);
    // If we have 10 entries, they're 0..9
    // If we are getting newest first, we want to return 9..4, then 4..0

    with_node_provider_rewards_log(|log| {
        // naive filtering implementation is okay b/c our data set is very small
        // (1/month for years will not give us much to work through for some time)
        // TODO - migrate to BTreeMap storage...
        let rewards = log
            .iter()
            .flat_map(|rewards| {
                let timestamp = rewards
                    .version
                    .clone()
                    .and_then(|v| match v {
                        Version::Version1(v1) => Some(v1),
                    })
                    .and_then(|v1| v1.rewards)
                    .and_then(|rewards| Some(rewards.timestamp));

                if let Some(timestamp) = timestamp {
                    if timestamp >= start_timestamp && timestamp <= end_timestamp {
                        Some(rewards)
                    } else {
                        None
                    }
                } else {
                    return None;
                }
            })
            .collect::<Vec<_>>();

        let len: u64 = rewards.len().try_into().unwrap();

        let end_range = len.saturating_sub(page as u64 * limit);
        let start_range = end_range.saturating_sub(limit);
        let rewards = (start_range..end_range)
            .rev()
            .map(|index| rewards[index as usize].clone())
            .collect();

        if start_range == 0 {
            (None, rewards)
        } else {
            (Some(page + 1), rewards)
        }
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
