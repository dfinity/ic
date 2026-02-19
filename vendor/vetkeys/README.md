# vetKeys

This repository contains a set of tools designed to help canister developers as well as frontend developers integrate **vetKeys** into their Internet Computer (ICP) applications.

**vetKeys** – Verifiable Encrypted Threshold Keys – on the Internet Computer addresses the fundamental challenge of storing secrets on-chain by allowing cryptographic key derivation without exposing private keys to anyone but the user. By leveraging **threshold cryptography**, vetKeys make it possible to generate, transport, and use encrypted keys securely, unlocking **privacy-preserving smart contracts** and **externally verifiable randomness**.

In slightly more detail, vetKeys enables use cases such as:

- **Decentralized key management**, secure threshold key derivation without relying on a traditional PKI - only the user knows the key.
- **Threshold BLS Signatures**, enabling secure, decentralized signing of messages.
- **Identity Based Encryption (IBE)**, enabling secure communication between users without exchanging public keys.
- **Verifiable Random Beacons**, providing a secure source of verifiable randomness for decentralized applications.
- **Smart contract defined vetKeys**, defining the constraints for obtaining derived keys/BLS signatures/verifiable randomness.

The management canister API for vetKeys exposes two endpoints, one for retrieving a public key and another one for deriving encrypted keys.

```
vetkd_public_key : (vetkd_public_key_args) -> (vetkd_public_key_result);
vetkd_derive_key : (vetkd_derive_key_args) -> (vetkd_derive_key_result);
```

For more documentation on vetKeys and the management canister API, see the [vetKeys documentation](https://internetcomputer.org/docs/building-apps/network-features/vetkeys/introduction).

Please share your feedback on the [developer forum](https://forum.dfinity.org/t/threshold-key-derivation-privacy-on-the-ic/16560/179).

## Key Features

### **1. vetKeys Backend Library** ([Motoko](https://mops.one/ic-vetkeys), [Rust](https://crates.io/crates/ic-vetkeys)) - Supports canister developers

Tools to help canister developers integrate vetKeys into their Internet Computer (ICP) applications.

- **KeyManager** ([Motoko](https://mops.one/ic-vetkeys/docs/key_manager/KeyManager), [Rust](https://docs.rs/ic-vetkeys/latest/ic_vetkeys/key_manager/struct.KeyManager.html)) – a library for deriving and managing encrypted cryptographic keys.
- **EncryptedMaps** ([Motoko](https://mops.one/ic-vetkeys/docs/encrypted_maps/EncryptedMaps), [Rust](https://docs.rs/ic-vetkeys/latest/ic_vetkeys/encrypted_maps/struct.EncryptedMaps.html)) – a library for encrypting using vetkeys, and securely storing and sharing encrypted key-value pairs.
- **Utils** ([Rust](https://docs.rs/ic-vetkeys/latest/)) – Utility functions for working with vetKeys.

### **2. [vetKeys Frontend Library](./frontend/ic_vetkeys)** - Supports frontend developers

Tools for frontend developers to interact with VetKD enabled canisters.

- **[KeyManager](https://dfinity.github.io/vetkeys/classes/_dfinity_vetkeys_key_manager.KeyManager.html)** – Facilitates interaction with a KeyManager-enabled canister.
- **[EncryptedMaps](https://dfinity.github.io/vetkeys/classes/_dfinity_vetkeys_encrypted_maps.EncryptedMaps.html)** – Facilitates interaction with a EncryptedMaps-enabled canister.
- **[Utils](https://dfinity.github.io/vetkeys/modules/_dfinity_vetkeys.html)** – Utility functions for working with vetKeys.

### **3. vetKeys Example Applications** - Deployable to the IC with the click of a button

- **[Threshold BLS Signatures](examples/basic_bls_signing)** - Demonstrates how to use vetKeys to create a threshold BLS signing service.
- **[Identity-Based Encryption (IBE)](examples/basic_ibe)** - Shows how to implement secure messaging using Identity Based Encryption using Internet Identity Principals as encryption IDs.
- **[Timelock Encryption](examples/basic_timelock_ibe)** - Implements a secret-bid auction system where bids remain encrypted until the auction is opened.
- **[Password Manager](examples/password_manager)** - A secure, decentralized password manager using Encrypted Maps for vault-based password storage and sharing.
- **[Password Manager with Metadata](examples/password_manager_with_metadata)** - Extends the basic password manager to support unencrypted metadata alongside encrypted passwords.
- **[Encrypted Notes](examples/encrypted_notes_dapp_vetkd)** - A secure note-taking application that uses vetKeys for encryption and enables sharing notes between users without device management.
- **[Encrypted Chat](examples/encrypted_chat)** - An *unfinished prototype* for an end-to-end encrypted messaging application based on vetKeys.
