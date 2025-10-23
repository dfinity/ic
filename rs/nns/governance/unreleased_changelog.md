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

## Changed

* Following private neurons is now generally disallowed. There are some exceptions to this though: 
    * A private neuron P can be followed by another neuron N, if either they share a controller or N's controller is listed as P's hotkey.
    * Following private neurons on the topic `NeuronManagement` is not a subject of this limitation. Furthermore, following public neurons is always allowed.

* Following non-existing Neuron IDs is disallowed as well.

## Deprecated

## Removed

## Fixed

## Security
