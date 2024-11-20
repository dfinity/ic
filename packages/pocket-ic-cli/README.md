# PocketIC CLI: A CLI for PocketIC server

This package contains the PocketIC CLI which is a CLI for the PocketIC server in the package `pocket-ic-server`.

This CLI allows to interact with a PocketIC server without using any PocketIC library, e.g., directly in the terminal.

The only supported use case at the moment is adding controllers to a canister deployed to an existing PocketIC instance on a PocketIC server.
Afterwards, existing tooling such as DFX can be used to interact with such a canister.

## Usage

```bash
pocket-ic-cli --server-url http://localhost:$(dfx info replica-port) canister --instance-id 0 --sender <existing-controller-id> <canister-id> update-settings --add-controller <new-controller-id>
```
