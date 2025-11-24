use crate::{
    pb::v1::{
        ArchivedMonthlyNodeProviderRewards, MonthlyNodeProviderRewards,
        archived_monthly_node_provider_rewards, archived_monthly_node_provider_rewards::Version,
    },
    storage::with_node_provider_rewards_log,
};

// Filter type
#[derive(Default)]
pub struct DateRangeFilter {
    pub(crate) start: Option<u64>,
    pub(crate) end: Option<u64>,
}

// Conversion from API type
impl From<ic_nns_governance_api::DateRangeFilter> for DateRangeFilter {
    fn from(filter: ic_nns_governance_api::DateRangeFilter) -> Self {
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
        // Since len > 0, len - 1 will not underflow.
        log.get(len - 1)
    })
}

pub(crate) fn list_node_provider_rewards(
    limit: usize,
    date_filter: Option<DateRangeFilter>,
) -> Vec<ArchivedMonthlyNodeProviderRewards> {
    let date_filter = date_filter.unwrap_or_default();
    let start_timestamp = date_filter.start.unwrap_or(0);
    let end_timestamp = date_filter.end.unwrap_or(u64::MAX);

    with_node_provider_rewards_log(|log| {
        // naive filtering implementation is okay b/c our data set is very small
        // (1/month for years will not give us much to work through for some time)
        // TODO - migrate to BTreeMap storage with keys as dates and change this to use range lookup
        let rewards = log
            .iter()
            .filter(|rewards| {
                // we drill down to get the timestamp and compare it to the filters
                rewards
                    .version
                    .clone()
                    .map(|v| match v {
                        Version::Version1(v1) => v1,
                    })
                    .and_then(|v1| v1.rewards)
                    .map(|rewards| rewards.timestamp)
                    .map(|ts| ts >= start_timestamp && ts <= end_timestamp)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();

        // Most recent rewards first
        rewards.into_iter().rev().take(limit).collect()
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
            start_date: None,
            end_date: None,
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
