# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* New proposal types:

    * `PauseCanisterMigrations` & `UnpauseCanisterMigrations`

    * `SetSubnetOperationalLevel`

        * Mainly, this sets the `is_halted` field in `SubnetRecord`.

        * This also sets a couple other things:
            * `ssh_readonly_access` - Also in `SubnetRecord`.
            * `ssh_node_state_write_access` - In `NodeRecord` (not `SubnetRecord`!).

        * Motivation: This will be used in a slightly enhanced subnet recovery
          procedure. This is needed before we can fully enable SEV.

* A new API function `get_neuron_index` is added. It accepts an exclusive lower bound on the neuron ID and a page size, and returns all neurons whose IDs are greater than the specified lower bound.

## Changed

## Deprecated

## Removed

## Fixed

## Security
