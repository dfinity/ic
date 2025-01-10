# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

### Support for node redeployment and node replacement even if it's in a subnet.

During node redeployments support for replacing an existing node with the same
IP address even if the existing node is currently in a subnet.
The new node id will be added to the subnet and the old node id will be removed
from the subnet without any intervention being required from the users or the community.

Previously, a proposal for removing and replacing the old node in the subnet was
required to enable redeployments for such nodes.
Such behavior is conservative and not strictly necessary since the subnet
decentralization is not affected if the new node has all properties
identical as the old node.

## Deprecated

## Removed

## Fixed

## Security
