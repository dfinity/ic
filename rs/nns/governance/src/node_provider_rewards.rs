use crate::{
    pb::{
        storage::{archived_monthly_node_provider_rewards, ArchivedMonthlyNodeProviderRewards},
        v1::MonthlyNodeProviderRewards,
    },
    storage::with_np_rewards_log,
};

pub(crate) fn record_node_provider_rewards(most_recent_rewards: MonthlyNodeProviderRewards) {
    let rewards = ArchivedMonthlyNodeProviderRewards {
        version: Some(archived_monthly_node_provider_rewards::Version::Version1(
            archived_monthly_node_provider_rewards::V1 {
                rewards: Some(most_recent_rewards),
            },
        )),
    };

    with_np_rewards_log(|log| {
        log.append(&rewards).expect("TODO: panic message");
    })
}

pub(crate) fn latest_node_provider_rewards() -> Option<ArchivedMonthlyNodeProviderRewards> {
    with_np_rewards_log(|log| {
        let len = log.len();
        if len == 0 {
            return None;
        }
        let rewards = log.get(len - 1);
        rewards
    })
}
