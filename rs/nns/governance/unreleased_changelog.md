# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added an optional field `max_ingress_bytes_per_block` to `CreateSubnetPayload`
and `UpdateSubnetPayload` which, when present, will set a limit on how big the ingress payload can
be in blocks produced by the created/updated subnet.

## Changed

* Lowered the maximum page size of list_neurons to 50. The vast majority (> 95%)
  have no more than 50 neurons, so for them, this has no noticeable impact.

## Deprecated

## Removed

## Fixed

* The Bitcoin and Dogecoin Watchdog canisters are now considered "protocol"
  canisters; thus, proposals to upgrade these canisters now fall into the
  "Protocol Canister Management" topic, instead of the "Application Canister
  Management" topic.

## Security
