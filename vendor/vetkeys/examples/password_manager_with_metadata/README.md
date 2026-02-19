# VetKey Password Manager with Metadata

| Motoko backend | [![](https://icp.ninja/assets/open.svg)](http://icp.ninja/editor?g=https://github.com/dfinity/vetkeys/tree/main/examples/password_manager_with_metadata/motoko)|
| --- | --- |
| Rust backend | [![](https://icp.ninja/assets/open.svg)](http://icp.ninja/editor?g=https://github.com/dfinity/vetkeys/tree/main/examples/password_manager_with_metadata/rust) |

The **VetKey Password Manager** is an example application demonstrating how to use **VetKeys** and **Encrypted Maps** to build a secure, decentralized password manager on the **Internet Computer (IC)**. This application allows users to create password vaults, store encrypted passwords, and share vaults with other users via their **Internet Identity Principal**.

This version of the application extends the basic password manager by supporting unencrypted metadata, such as URLs and tags, alongside encrypted passwords. The goal is to demonstrate how to make atomic updates to the Encrypted Maps canister, storing both encrypted and unencrypted data in a single update call.

## Features

- **Secure Password Storage**: Uses VetKey to encrypt passwords before storing them in Encrypted Maps.
- **Vault-Based Organization**: Users can create multiple vaults, each containing multiple passwords.
- **Access Control**: Vaults can be shared with other users via their **Internet Identity Principal**.
- **Atomic Updates**: Stores encrypted passwords along with unencrypted metadata in a single update call.

## Setup

### Prerequisites

- [Local Internet Computer dev environment](https://internetcomputer.org/docs/building-apps/getting-started/install)
- [npm](https://www.npmjs.com/package/npm)

### (Optionally) Choose a Different Master Key

This example uses `test_key_1` by default. To use a different [available master key](https://internetcomputer.org/docs/building-apps/network-features/vetkeys/api#available-master-keys), change the `"init_arg": "(\"test_key_1\")"` line in `dfx.json` to the desired key before running `dfx deploy` in the next step.

### Deploy the Canisters Locally

If you want to deploy this project locally with a Motoko backend, then run:
```bash
dfx start --background && dfx deploy
```
from the `motoko` folder.

To use the Rust backend instead of Motoko, run the same command in the `rust` folder.

## Running the Project

### Backend

The backend consists of an **Encrypted Maps**-enabled canister that securely stores passwords. It is automatically deployed with `dfx deploy`.

### Frontend

The frontend is a **Svelte** application providing a user-friendly interface for managing vaults and passwords.

To run the frontend in development mode with hot reloading:

```bash
npm run dev
```

## Limitations

This example dapp does not implement key rotation, which is strongly recommended in a production environment.
Key rotation involves periodically changing encryption keys and re-encrypting data to enhance security.
In a production dapp, key rotation would be useful to limit the impact of potential key compromise if a malicious party gains access to a key, or to limit access when users are added or removed from note sharing.

## Additional Resources

- **[Basic Password Manager](../password_manager/)** - If you want a simpler example without metadata.
