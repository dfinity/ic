# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

### Topic-based following

The new `SetFollowing` neuron command allows following voting decisions based on proposal topics.

This command can be used to set or change following for any number of topics at once. Users
are encouraged to set following based on topics, although _legacy following_ (based on
individual proposal types) will still work until further notice. However, this command may clear
some legacy following if it becomes redundant, specifically, in the following cases:

1. Following on proposal types within the topics explicitly mentioned by `SetFollowing`.
2. Legacy catch-all following, if a neuron has topic-based following for all non-critical
    topics, or if the `SetFollowing` command mentions each non-critical topic.

For example:

```bash
dfx canister --ic call SNS_GOVERNANCE manage_neuron '(record {
  subaccount = FOLLOWER_NEURON_ID_BLOB;
  command = opt variant {
    SetFollowing = record {
      topic_following = vec {
        record {
          topic = opt variant { ApplicationBusinessLogic };
          followees = vec {
            record {
              alias = opt "Giuseppe Arcimboldo";
              neuron_id = opt record { id = FOLLOWEE_NEURON_ID_BLOB };
            };
          };
        };
        record {
          topic = opt variant { CriticalDappOperations };
          followees = vec {};
  }}}}})'
```

In this example, following on the `ApplicationBusinessLogic` topic is changed (from whatever has
been there before) to a single neuron, and following on `CriticalDappOperations` is being
removed.

Followee _aliases_ are option; they are currently used only when listing neurons being followed
(a.k.a. followees), which helps remember why a particular one has been added in the first place.

**Backward compatibility.**
Legacy following still works for proposal types and for neurons that do not have any topic-based
following for covering that proposal type. For example, after executing the following command,
the modified neuron would still follow on, e.g., `DeregisterDappCanisters` proposals, assuming
it had followed some neuron on this proposal type.

Topic-based following takes precedence over legacy following, e.g., regardless of which
legacy following has been set up for the neuron modified in the above example, that neuron will
now only follow Giuseppe Arcimboldo on proposals within the `ApplicationBusinessLogic` topic.

Legacy _catch-all_ following is also still supported for neurons that follow on the respective
special proposal type `0`, but only for neurons that do not already follow on the specific topic
in question (nor follow on the specific proposal type being voted on). In other words, catch-all
has the lowest precedence, and topic-based following now has the highest.

### Filtering proposals by topic

`SnsGov.list_proposals` now supports filtering by proposal topic. For example, the following
command can be used to list proposals that are either under the `Governance` topic or do not specify
a topic:

```sh
dfx canister SNS_GOVERNANCE call list_proposals '(
  record {
    include_reward_status = vec {};
    limit = 0 : nat32;
    exclude_type = vec {};
    include_status = vec {};
    include_topic = opt vec {
      record { topic = null };
      record { topic = opt variant { Governance } };
    };
  },
)'
```

If `include_topic` is not mentioned or `null`, then proposals are listed regardless of their topic.

## Changed

## Deprecated

* Custom proposals that were not yet assigned to a topic are no longer allowed to be submitted.

## Removed

## Fixed

## Security
