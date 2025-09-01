# Changelog

INSERT NEW RELEASES HERE

* Replicated execution of the query endpoints `get_node_provider_rewards_calculation` and `get_historical_reward_periods`
  is disabled.

# 2025-08-15: Proposal 137910

http://dashboard.internetcomputer.org/proposal/137910

* Hourly sync nodes metrics, in preparation for performance based rewards calculation.
* Extract rewardable nodes between two timestamps, in preparation for performance based rewards calculation.
* Compute daily failure rate extrapolation in rewards-calculation lib., in preparation for performance based rewards
  calculation.
* Add telemetry for the canister
* Removed the registry store cleanup function, which was previously used to resynchronize registry data with timestamp
  to registry versions mapping.

# 2025-07-11: Proposal 137348

http://dashboard.internetcomputer.org/proposal/137348

# Added

* Support registry timestamps internally, in preparation for reward calculation changes.
* Add storage for node metrics.

# 2025-06-10: Proposal 136893

http://dashboard.internetcomputer.org/proposal/136893

* Added performance-based rewards. This is mostly based on successful/failed block production.

* Added a max_rewardable_nodes field to each node operator. Not used yet, but in
  the future, it will limit how many nodes a node operator can onboard (per type).

# 2025-04-25: Proposal 136372

http://dashboard.internetcomputer.org/proposal/136372

## Fixed

* Fixed a bug with the registry client that prevented the canister from reading registry data when there were deletions.
* Limit 'get_node_providers_monthly_xdr_rewards' to only be callable from NNS Governance.
* Use `StableBTreeMap::init` instead of `::new` for registry state.

# 2025-04-11: Proposal 136226

http://dashboard.internetcomputer.org/proposal/136226

## Added

* The Node Reward Canister will now perform the calculations that the Registry canister performs for node provider
  rewards.

# 2025-04-05: Proposal 136072

http://dashboard.internetcomputer.org/proposal/136072

## Added

* The Node Reward Canister will now sync changes from the Registry canister.

# 2025-03-17: Proposal

## Added

* A Node Rewards canister is created which will eventually assume the role of calculating ICP rewards
  for node providers based on the nodes that are running. It will take this responsibility from the
  Registry canister, so it can evolve in a more robust way based on additional performance data.

