# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

## Fixed

## Security

Enforce a lower bound for `min_participant_icp_e8s` of `1_000_000`.

TODO: Due to the common dependency of NNS Governance and SNS-W on rs/sns/init,
TODO: it is required that the NNS Governance release with the change announces above
TODO: is released *before* the analogous SNS-W release. Therefore, SNS-W should not
TODO: be released until May 30th.