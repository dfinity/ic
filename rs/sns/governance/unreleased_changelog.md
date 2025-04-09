# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added the `SetFollowing` neuron command that allows setting up following based on proposal topics.

    This command can be used to set or change following for any number of topics at once.

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
    _Legacy_ following (i.e., following based on individual proposal types) still works
    for proposal types and for neurons that do not have any topic-based following for covering that
    proposal type. For example, after executing the following command, the modified neuron would
    still follow on, e.g., `DeregisterDappCanisters` proposals, assuming it had followed some neuron
    on this proposal type.

    Topic-based following takes precedence over legacy following, e.g., regardless of which
    legacy following has been set up for the neuron modified in the above example, that neuron will
    now only follow Giuseppe Arcimboldo on proposals within the `ApplicationBusinessLogic` topic.

    Legacy _catch-all_ following is also still supported for neurons that follow on the respective
    special proposal type `0`, but only for neurons that do not already follow on the specific topic
    in question (nor follow on the specific proposal type being voted on). In other words, catch-all
    has the lowest precedence, and topic-based following now has the highest.

## Changed

## Deprecated

## Removed

## Fixed

## Security
