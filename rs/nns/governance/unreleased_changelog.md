# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

### List Neurons Paging

In the case where more than 500 neurons would be returned from the API, the API will now
return a `next_start_from_neuron_id` field in the response. The value can then be added
to the next request to get the next set of neurons.

This will only affect neuron holders with more than 500 neurons, which is a small minority.

The advantage of this is that is now possible for neuron holders with many inactive neurons
to list all of their neurons, while also limiting the amount of work the endpoint does in a 
single request.

### Periodic Confirmation

Enabled voting power adjustment and follow pruning.

#### Prior Work

This section describes related changes in previous releases.

We already started recording how long it's been since neurons have confirmed
their following (aka refreshed voting power). Neurons were also given the
ability to confirm their following. Those who have never confirmed are
considered as having refreshed on Sep 1, 2024.

This feature was proposed and approved in motion [proposal 132411].

[proposal 132411]: https://dashboard.internetcomputer.org/proposal/132411

#### New Behavior(s) (In This Release)

With this enablement, not refreshing for more than 6 months will start to affect
the neuron. More precisely,

1. If a neuron has not refreshed in 6 months, then votes have less influence on
   the outcome of proposals.

2. If a neuron has not refreshed in 7 months,

    a. It stops following other neurons (except on the NeuronManagement topic;
       those followees are retained).

    b. Its influence on proposals goes to 0.

## Changed

* `InstallCode` proposal payload hashes are now computed when making the proposal instead of when
  listing proposal. Hashes for existing proposals are backfilled.

## Deprecated

## Removed

## Fixed

## Security
