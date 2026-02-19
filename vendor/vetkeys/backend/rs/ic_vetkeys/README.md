# Internet Computer (IC) vetKeys

This crate contains a set of tools designed to help canister developers integrate **vetKeys** into their Internet Computer (ICP) applications.

The current Minimum Supported Rust Version (MSRV) of this crate is 1.85. Any future increase in the MSRV will be accompanied by a bump in the minor version number.

## [Key Manager](https://docs.rs/ic-vetkeys/latest/ic_vetkeys/key_manager/struct.KeyManager.html)
A canister library for derivation of encrypted vetkeys from arbitrary strings. It can be used in combination with the [frontend key manager library](https://dfinity.github.io/vetkeys/classes/_dfinity_vetkeys_key_manager.KeyManager.html).

## [Encrypted Maps](https://docs.rs/ic-vetkeys/latest/ic_vetkeys/encrypted_maps/struct.EncryptedMaps.html)
An efficient canister library facilitating access control and encrypted storage for a collection of maps contatining key-value pairs. It can be used in combination with the [frontend encrypted maps library](https://dfinity.github.io/vetkeys/classes/_dfinity_vetkeys_encrypted_maps.EncryptedMaps.html).

## [Utils](https://docs.rs/ic-vetkeys/latest/)
For obtaining and decrypting verifiably-encrypted threshold keys via the Internet Computer vetKD system API. The API is located in the crate root.

## Cross-language library
If Motoko better suits your needs, take a look at the [Motoko equivalent of this library](https://mops.one/ic-vetkeys).
