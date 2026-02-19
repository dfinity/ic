# Encrypted notes: vetKD

| Motoko backend | [![](https://icp.ninja/assets/open.svg)](http://icp.ninja/editor?g=https://github.com/dfinity/vetkeys/tree/main/examples/encrypted_notes_dapp_vetkd/motoko)|
| --- | --- |
| Rust backend | [![](https://icp.ninja/assets/open.svg)](http://icp.ninja/editor?g=https://github.com/dfinity/vetkeys/tree/main/examples/encrypted_notes_dapp_vetkd/rust) |

Encrypted notes is an example dapp for authoring and storing confidential information on the Internet Computer (ICP) in the form of short pieces of text. Users can create and access their notes via any number of automatically synchronized devices authenticated via Internet Identity (II). Notes are stored confidentially using vetKeys. The end-to-end encryption is performed by the dapp’s frontend.

In particular, the notes are encrypted with an AES key that is derived (directly in the browser) from a note-ID-specific vetKey obtained from the backend canister (in encrypted form, using an ephemeral transport key), which itself obtains it from the vetKD system API. This way, there is no need for any device management in the dapp, plus sharing of notes becomes possible.

The vetKey used to encrypt and decrypt a note is note-ID-specific (and not, for example, principal-specific) to enable the sharing of notes between users. The derived AES keys are stored as non-extractable CryptoKeys in an IndexedDB in the browser for efficiency so that their respective vetKey only has to be fetched from the server once. To improve the security even further, the vetKeys' derivation information could be adapted to include a (numeric) epoch that advances each time the list of users with which the note is shared is changed.

## Prerequisites

This example requires an installation of:

- [x] Install the [IC SDK](https://internetcomputer.org/docs/current/developer-docs/setup/install/index.mdx).
- [x] Install [npm](https://www.npmjs.com/package/npm).

### (Optionally) Choose a Different Master Key

This example uses `test_key_1` by default. To use a different [available master key](https://internetcomputer.org/docs/building-apps/network-features/vetkeys/api#available-master-keys), change the `"init_arg": "(\"test_key_1\")"` line in `dfx.json` to the desired key before running `dfx deploy` in the next step.

## Deploy the Canisters Locally

If you want to deploy this project locally with a Motoko backend, then run:
```bash
dfx start --background && dfx deploy
```
from the `motoko` folder.

To use the Rust backend instead of Motoko, run the same command in the rust folder.

## Example Components

### Backend

The backend consists of a canister that stores encrypted notes. It is automatically deployed with `dfx deploy`.

### Frontend

The frontend is a **Svelte** application providing a user-friendly interface for managing encrypted notes.

To run the frontend in development mode with hot reloading (after running `dfx deploy`):

```bash
npm run dev
```

## Limitations

This example dapp does not implement key rotation, which is strongly recommended in a production environment.
Key rotation involves periodically changing encryption keys and re-encrypting data to enhance security.
In a production dapp, key rotation would be useful to limit the impact of potential key compromise if a malicious party gains access to a key, or to limit access when users are added or removed from note sharing.

## Troubleshooting

If you run into issues, clearing all the application-specific IndexedDBs in the browser (which are used to store Internet Identity information and the derived non-extractable AES keys) might help fix the issue. For example in Chrome, go to Inspect → Application → Local Storage → `http://localhost:3000/` → Clear All, and then reload.
