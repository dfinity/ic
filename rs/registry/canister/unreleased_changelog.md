# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* Allow unassigned nodes to have nonempty ssh_node_state_write_access.

  * Why: Previously, it was believed that there is no way that a nonempty
    ssh_node_state_write_access could be used constructively, but after
    consulting the Consensus team, we (the Governance team) learned that this is
    not true. In particular, it could be useful during a subnet recovery, even
    though this capability generally wouldn't be used during a "typical" subnet
    recovery.

## Deprecated

## Removed

## Fixed

## Security
