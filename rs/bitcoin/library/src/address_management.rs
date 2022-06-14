use crate::{
    AddAddressWithParametersError, BitcoinAgent, BitcoinCanister, EcdsaPubKey, UtxosState,
    STABILITY_THRESHOLD,
};
use bitcoin::{
    blockdata::{opcodes, script::Builder},
    hashes::Hash,
    secp256k1,
    secp256k1::Secp256k1,
    util::{
        address::Payload,
        bip32::{ChainCode, ChildNumber, ExtendedPubKey},
    },
    Address, AddressType, Network, PrivateKey, PublicKey, ScriptHash,
};
use std::{cell::RefCell, error::Error};

// A private key in WIF (wallet import format). This is only for demonstrational
// purposes. When the Bitcoin integration is released on mainnet, canisters will
// have the ability to securely generate ECDSA keys.
const BTC_PRIVATE_KEY_WIF: &str = "L2C1QgyKqNgfV7BpEPAm6PVn2xW8zpXq6MojSbWdH18nGQF2wGsT";

thread_local! {
    static BTC_PRIVATE_KEY: RefCell<PrivateKey> =
        RefCell::new(PrivateKey::from_wif(BTC_PRIVATE_KEY_WIF).unwrap());
}

/// Returns the Bitcoin private key.
pub(crate) fn get_btc_private_key() -> PrivateKey {
    BTC_PRIVATE_KEY.with(|private_key| *private_key.borrow())
}

/// Returns the Bitcoin ECDSA public key from a given public key.
pub(crate) fn get_btc_ecdsa_public_key_from_public_key(public_key: &PublicKey) -> EcdsaPubKey {
    // TODO(ER-2617): Add support for public child key derivation from a given derivation path (should use tECDSA to get the canister’s `ExtendedPubKey`).
    EcdsaPubKey {
        public_key: public_key.to_bytes(),
        chain_code: Vec::from([0; 32]),
        derivation_path: vec![],
    }
}

/// Returns the Bitcoin public key.
pub(crate) fn get_btc_public_key() -> PublicKey {
    get_btc_private_key().public_key(&Secp256k1::new())
}

/// Returns the Bitcoin ECDSA public key.
pub(crate) fn get_btc_ecdsa_public_key() -> EcdsaPubKey {
    get_btc_ecdsa_public_key_from_public_key(&get_btc_public_key())
}

/// Returns the public key from a given Bitcoin ECDSA public key.
pub(crate) fn get_btc_public_key_from_ecdsa_public_key(
    ecdsa_public_key: &EcdsaPubKey,
) -> Result<PublicKey, bitcoin::util::key::Error> {
    PublicKey::from_slice(&ecdsa_public_key.public_key)
}

/// Returns the `ChildNumber` (u31) associated with a given vector of less than four `u8`s.
/// Assuming that the first bit is zero, making `child_bytes` always corresponds to an unhardened derivation path.
/// It is the case by following the only possible code path to reach `get_child_number`.
fn get_child_number(child_bytes: &[u8]) -> ChildNumber {
    let mut index = (child_bytes[0] as u32) << 24;
    if child_bytes.len() > 1 {
        index |= (child_bytes[1] as u32) << 16;
        if child_bytes.len() > 2 {
            index |= (child_bytes[2] as u32) << 8;
            if child_bytes.len() > 3 {
                index |= child_bytes[3] as u32;
            }
        }
    }
    ChildNumber::Normal { index }
}

/// Return a valid [BIP-32 derivation path](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key).
///
/// Each byte string (`blob`) in the `derivation_path` must be a 4-byte
/// big-endian encoding of an unsigned integer less than 2^31 for non-hardened key derivation.
pub fn get_derivation_path(input: &[u8]) -> Vec<Vec<u8>> {
    // Below there is an example of how indexes changes for each iteration. Each column represents
    // setting a bit in the result:
    //
    // i   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 ...
    // ip  0                       1                       2                       3                       4    ...
    // iz  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1 ...
    // cp  0                    1                       2                       3                       0       ...
    // cz  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  1  2  3 ...
    //
    // e.g. for i = 23, we set the bit 0 of the current word at position 3 to the value of the bit 7
    //      of the input word at position 2

    let mut res = Vec::new(); // the final result of this function
    let mut buff: [u8; 4] = [0; 4]; // buffer for the next 4-byte word to be put into the result
    for i in 0..(8 * input.len()) {
        // the position in the "flattened" input
        let y = i % 31; // flush to res when y == 0
        if i > 0 && y == 0 {
            // curr is completed, flush and clear it
            res.push(buff.to_vec());
            buff = [0; 4];
        }
        // we need to set a bit in curr to the value of i in input. We do this in 2 steps:

        // 1) set b to the value of the current bit in input
        let ip = i / 8; // position in input
        let iz = i % 8; // position in input[ip]
        let b = 0x80 & (input[ip] << iz); // store the bit in the most significant bit

        // 2) set the bit in curr. Note that we need the +1 because the most important bit is always 0
        let cp = (y + 1) / 8; // position in curr
        let cz = (y + 1) % 8; // position in curr[p]
        buff[cp] |= b >> cz;
    }
    if input.len() % 8 != 0 {
        res.push(buff.to_vec());
    }

    res
}

/// Adds an address based on the provided derivation path and address type to the list of managed addresses.
/// A minimum number of confirmations must further be specified, which is used when calling `get_utxos` and `get_balance`.
/// Returns the derived address if the operation is successful and an error otherwise.
pub(crate) fn add_address_with_parameters(
    bitcoin_agent: &mut BitcoinAgent<impl BitcoinCanister>,
    derivation_path: &[u8],
    address_type: &crate::AddressType,
    min_confirmations: u32,
) -> Result<Address, AddAddressWithParametersError> {
    if min_confirmations > STABILITY_THRESHOLD {
        return Err(AddAddressWithParametersError::MinConfirmationsTooHigh);
    }
    if 8 * derivation_path.len() > 255 * 31 {
        return Err(AddAddressWithParametersError::DerivationPathTooLong);
    }
    // TODO(ER-2617): Add support for public child key derivation from a given derivation path (should modify bip32 crate in order to support extended BIP-32 derivation path (including “arbitrary“ length) instead of using `get_derivation_path`).
    let address = add_address_from_unhardened_path(
        bitcoin_agent,
        &get_derivation_path(derivation_path),
        address_type,
        min_confirmations,
    );
    Ok(address)
}

/// Returns the public key and address of the derived child from the given public key, chain code, derivation path, address type and network.
pub(crate) fn derive_ecdsa_public_key_and_address_from_unhardened_path(
    derivation_path: &[Vec<u8>],
    address_type: &crate::AddressType,
    network: &Network,
    ecdsa_public_key: &EcdsaPubKey,
) -> (EcdsaPubKey, Address) {
    let child_number_vec: Vec<ChildNumber> = derivation_path
        .iter()
        .map(|child_bytes| get_child_number(child_bytes))
        .collect();
    let parent_extended_public_key = ExtendedPubKey {
        network: *network,
        depth: 0,
        parent_fingerprint: Default::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key: secp256k1::PublicKey::from_slice(&ecdsa_public_key.public_key).unwrap(),
        chain_code: ChainCode::from(&*ecdsa_public_key.chain_code),
    };
    let child_extended_public_key = parent_extended_public_key
        .derive_pub(&Secp256k1::new(), &child_number_vec)
        .unwrap();
    let public_key = PublicKey {
        compressed: true,
        inner: secp256k1::PublicKey::from_slice(&child_extended_public_key.public_key.serialize())
            .unwrap(),
    };
    let child_ecdsa_public_key = EcdsaPubKey {
        public_key: public_key.to_bytes(),
        chain_code: Vec::from(child_extended_public_key.chain_code.to_bytes()),
        derivation_path: ecdsa_public_key
            .derivation_path
            .iter()
            .cloned()
            .chain(derivation_path.iter().cloned())
            .collect(),
    };
    let address = get_address(network, address_type, &child_ecdsa_public_key).unwrap();

    (child_ecdsa_public_key, address)
}

/// Adds the address for the given unhardened derivation path and address type to the given BitcoinAgent if the derived address is not already managed.
/// This function assumes that the passed derivation path is an unhardened path. This assumption has to be checked in the caller function.
pub(crate) fn add_address_from_unhardened_path(
    bitcoin_agent: &mut BitcoinAgent<impl BitcoinCanister>,
    derivation_path: &[Vec<u8>],
    address_type: &crate::AddressType,
    min_confirmations: u32,
) -> Address {
    let (ecdsa_public_key, address) = derive_ecdsa_public_key_and_address_from_unhardened_path(
        derivation_path,
        address_type,
        &bitcoin_agent.bitcoin_canister.get_network(),
        &get_btc_ecdsa_public_key(),
    );
    if !bitcoin_agent.ecdsa_pub_key_addresses.contains_key(&address) {
        bitcoin_agent
            .ecdsa_pub_key_addresses
            .insert(address.clone(), ecdsa_public_key);
        let utxos_state = UtxosState::new(min_confirmations);
        bitcoin_agent
            .utxos_state_addresses
            .insert(address.clone(), utxos_state);
    }
    address
}

/// Removes the given address from given BitcoinAgent managed addresses.
/// The address is removed if it is already managed and if it is different from the main address.
/// Returns true if the removal was successful, false otherwise.
pub(crate) fn remove_address(
    bitcoin_agent: &mut BitcoinAgent<impl BitcoinCanister>,
    address: &Address,
) -> bool {
    let address_can_be_removed = bitcoin_agent.ecdsa_pub_key_addresses.contains_key(address)
        && *address != bitcoin_agent.get_main_address();
    if address_can_be_removed {
        bitcoin_agent.ecdsa_pub_key_addresses.remove(address);
        bitcoin_agent.utxos_state_addresses.remove(address);
    }
    address_can_be_removed
}

/// Returns the managed addresses according to given BitcoinAgent.
pub(crate) fn list_addresses(bitcoin_agent: &BitcoinAgent<impl BitcoinCanister>) -> Vec<&Address> {
    bitcoin_agent.ecdsa_pub_key_addresses.keys().collect()
}

/// Returns the P2PKH address from a given network and public key.
pub(crate) fn get_p2pkh_address(
    network: &Network,
    ecdsa_public_key: &EcdsaPubKey,
) -> Result<Address, Box<dyn Error>> {
    Ok(Address::p2pkh(
        &get_btc_public_key_from_ecdsa_public_key(ecdsa_public_key)?,
        *network,
    ))
}

/// Returns the P2SH address from a given network and script hash.
pub(crate) fn get_p2sh_address(
    network: &Network,
    script_hash: &[u8],
) -> Result<Address, Box<dyn Error>> {
    Ok(Address {
        network: *network,
        payload: Payload::ScriptHash(ScriptHash::from_slice(script_hash)?),
    })
}

/// Returns the P2SH address from a given network and public key.
pub(crate) fn get_p2sh_address_for_pub_key(
    network: &Network,
    ecdsa_public_key: &EcdsaPubKey,
) -> Result<Address, Box<dyn Error>> {
    let public_key = get_btc_public_key_from_ecdsa_public_key(ecdsa_public_key)?;
    let public_key_hash = public_key.pubkey_hash();
    let script = Builder::new()
        .push_slice(&public_key_hash[..])
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    get_p2sh_address(network, &script.script_hash().to_ascii_lowercase())
}

/// Returns the P2WPKH address from a given network and public key.
pub(crate) fn get_p2wpkh_address(
    network: &Network,
    ecdsa_public_key: &EcdsaPubKey,
) -> Result<Address, Box<dyn Error>> {
    Ok(Address::p2wpkh(
        &get_btc_public_key_from_ecdsa_public_key(ecdsa_public_key)?,
        *network,
    )?)
}

/// Returns the Bitcoin address from a given network, address type and ECDSA public key.
fn get_address(
    network: &Network,
    address_type: &crate::AddressType,
    ecdsa_public_key: &EcdsaPubKey,
) -> Result<Address, Box<dyn Error>> {
    match get_bitcoin_address_type(address_type) {
        AddressType::P2pkh => get_p2pkh_address(network, ecdsa_public_key),
        AddressType::P2sh => get_p2sh_address_for_pub_key(network, ecdsa_public_key),
        AddressType::P2wpkh => get_p2wpkh_address(network, ecdsa_public_key),
        // TODO (ER-2639): Add more address types (especially P2tr and P2wsh)
        // Other cases can't happen see BitcoinAgent::new
        _ => panic!(),
    }
}

/// Returns the Bitcoin address for a given network, address type, and ECDSA public key.
pub(crate) fn get_main_address(network: &Network, address_type: &crate::AddressType) -> Address {
    get_address(network, address_type, &get_btc_ecdsa_public_key()).unwrap()
}

/// Returns the bitcoin::AddressType converted from an crate::AddressType
pub(crate) fn get_bitcoin_address_type(address_type: &crate::AddressType) -> AddressType {
    match address_type {
        crate::AddressType::P2pkh => AddressType::P2pkh,
        crate::AddressType::P2sh => AddressType::P2sh,
        crate::AddressType::P2wpkh => AddressType::P2wpkh,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{agent, canister_mock::BitcoinCanisterMock};
    use std::{collections::HashSet, str::FromStr};

    /// Returns the parsed `AddressType` based on a generated address of given `address_type`.
    fn get_parsed_address_type_from_generated_address(
        address_type: &crate::AddressType,
    ) -> AddressType {
        let bitcoin_agent = agent::new_mock(&Network::Regtest, address_type);
        bitcoin_agent.get_main_address().address_type().unwrap()
    }

    /// Check that `get_main_address` returns an address of the correct type according to Bitcoin agent `main_address_type`.
    #[test]
    fn check_get_main_address() {
        for address_type in &[
            crate::AddressType::P2pkh,
            crate::AddressType::P2sh,
            crate::AddressType::P2wpkh,
        ] {
            assert_eq!(
                get_parsed_address_type_from_generated_address(address_type),
                get_bitcoin_address_type(address_type)
            )
        }
    }

    /// Returns `bitcoin_agent` addresses as a `Vec<Address>`
    fn list_addresses(bitcoin_agent: &BitcoinAgent<BitcoinCanisterMock>) -> Vec<Address> {
        bitcoin_agent
            .list_addresses()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Returns a `HashSet<Address>` from the given address vector reference.
    fn to_hashset(v: &[Address]) -> HashSet<Address> {
        HashSet::from_iter(v.iter().cloned())
    }

    /// Returns true if the two given vector references contain the same addresses without considering the order, otherwise false.
    fn contains_same_addresses(v0: &[Address], v1: &[Address]) -> bool {
        to_hashset(v0) == to_hashset(v1)
    }

    /// Check that `add_address`, `remove_address` and `list_addresses` respectively add, remove and list managed addresses.
    #[test]
    fn check_managed_addresses() {
        let address_type = &crate::AddressType::P2pkh;
        let bitcoin_agent = &mut agent::new_mock(&Network::Regtest, address_type);
        let mut addresses = list_addresses(bitcoin_agent);

        let address = bitcoin_agent.add_address(&[0]).unwrap();

        addresses.push(address.clone());
        assert!(contains_same_addresses(
            &list_addresses(bitcoin_agent),
            &addresses
        ));

        assert!(bitcoin_agent.remove_address(&address));
        addresses.pop();
        assert!(contains_same_addresses(
            &list_addresses(bitcoin_agent),
            &addresses
        ));
    }

    /// Check that the public key and address of the derived child match those expected from the given public key, chain code and derivation path.
    fn test_derive_ecdsa_public_key_and_address_from_unhardened_path(
        public_key: &str,
        chain_code_vec: &str,
        derivation_path: &[Vec<u8>],
        expected_child_public_key: &str,
        expected_child_address: &str,
    ) {
        let (ecdsa_public_key, address) = derive_ecdsa_public_key_and_address_from_unhardened_path(
            derivation_path,
            &crate::AddressType::P2pkh,
            &Network::Bitcoin,
            &EcdsaPubKey {
                public_key: PublicKey::from_str(public_key).unwrap().to_bytes(),
                chain_code: hex::decode(chain_code_vec).unwrap(),
                derivation_path: vec![],
            },
        );
        assert_eq!(
            ecdsa_public_key.public_key.to_vec(),
            hex::decode(expected_child_public_key).unwrap()
        );
        assert_eq!(address.to_string(), expected_child_address);
    }

    #[test]
    fn test_derive_ecdsa_public_key_and_address_from_unhardened_path_2147483647() {
        test_derive_ecdsa_public_key_and_address_from_unhardened_path(
            "03adbe4f86c26994a97446fb8fb3d35189c9ebf3f38a2fce23d49f811edb6f2d0e",
            "7373848171c5f79874eb0a85cba84618dccf29a71874df69dfc6b5c8370d6018",
            &[vec![0x7F, 0xFF, 0xFF, 0xFF]],
            "037b285fd479b64c9d8ebe089847bfc1268d5fed1882fababe48144544fd9fdbfe",
            "19pwaccNmLtmCag1WgRjNHgMTJ7CWcJJu4",
        );
    }

    #[test]
    fn test_derive_ecdsa_public_key_and_address_from_unhardened_path_1_2_3() {
        test_derive_ecdsa_public_key_and_address_from_unhardened_path(
            "023e4740d0ba639e28963f3476157b7cf2fb7c6fdf4254f97099cf8670b505ea59",
            "180c998615636cd875aa70c71cfa6b7bf570187a56d8c6d054e60b644d13e9d3",
            &[vec![0, 0, 0, 1], vec![0, 0, 0, 2], vec![0, 0, 0, 3]],
            "0256114e0a599ae104c908daf2de6c0622eafb352f16452e956d3f6cf59be675a8",
            "1JnJVbQ9feEmwrwT4NzrEC3MAffg3uMmH4",
        );
    }

    #[test]
    fn test_get_derivation_path_0x00() {
        assert_eq!(
            vec![vec![0x00, 0x00, 0x00, 0x00]],
            get_derivation_path(&[0x00])
        );
    }

    #[test]
    fn test_get_derivation_path_0xff() {
        assert_eq!(
            vec![vec![0x7f, 0x80, 0x00, 0x00]],
            get_derivation_path(&[0xff])
        );
    }

    #[test]
    fn test_get_derivation_path_0x05() {
        assert_eq!(
            vec![vec![0x02, 0x80, 0x00, 0x00]],
            get_derivation_path(&[0x05])
        );
    }

    #[test]
    fn test_get_derivation_path_0x96() {
        assert_eq!(
            vec![vec![0x4b, 0x00, 0x00, 0x00]],
            get_derivation_path(&[0x96])
        );
    }

    #[test]
    fn test_get_derivation_path_0x00_0x00() {
        assert_eq!(
            vec![vec![0x00, 0x00, 0x00, 0x00]],
            get_derivation_path(&[0x00, 0x00])
        );
    }

    #[test]
    fn test_get_derivation_path_0xff_0xff() {
        assert_eq!(
            vec![vec![0x7f, 0xff, 0x80, 0x00]],
            get_derivation_path(&[0xff, 0xff])
        );
    }

    #[test]
    fn test_get_derivation_path_0x05_0x05() {
        assert_eq!(
            vec![vec![0x02, 0x82, 0x80, 0x00]],
            get_derivation_path(&[0x05, 0x05])
        );
    }

    #[test]
    fn test_get_derivation_path_0x96_0x75() {
        assert_eq!(
            vec![vec![0x4b, 0x3a, 0x80, 0x00]],
            get_derivation_path(&[0x96, 0x75])
        );
    }

    #[test]
    fn test_get_derivation_path_0x00_0x00_0x00_0x00() {
        assert_eq!(
            vec![vec![0x00, 0x00, 0x00, 0x00], vec![0x00, 0x00, 0x00, 0x00]],
            get_derivation_path(&[0x00, 0x00, 0x00, 0x00])
        )
    }

    #[test]
    fn test_get_derivation_path_0xff_0xff_0xff_0xff() {
        assert_eq!(
            vec![vec![0x7f, 0xff, 0xff, 0xff], vec![0x40, 0x00, 0x00, 0x00]],
            get_derivation_path(&[0xff, 0xff, 0xff, 0xff])
        );
    }

    #[test]
    fn test_get_derivation_path_principal_fxlwyaxqguck7wzqtmgf3obzov5l7twcige5ch7amy63w5aoizpqe() {
        // Dear reviewer, I know what you are thinking and yes, this test is nightmare to
        // understand and review. Let me try help you with it.
        //
        // [BIP-32 derivation paths](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key)
        // are arrays of blobs where each blob is composed by 4 bytes. The first bit of the first
        // byte, i.e. the most significant bit, is always 0.
        //
        // Given an array of bytes called `input`, how can you calculate manually the `expected` result?
        //
        // First of all, each vec of `expected` is equivalent to 4 bytes of `input` shifted right by
        // the position of the vec itself inside expected.
        // For instance, the vec number 1 of `expected` is composed by the first 4 bytes of `input`
        // shifted right by 1:
        // * 0b_1111_0000 >> 1 => 0b_0111_1000
        // * 0b_0011_0101 >> 1 => 0b_0001_1010
        // * 0b_0000_0100 >> 1 => 0b_1000_0010
        // * 0b_1010_1111 >> 1 => 0b_0101_0111
        //
        // Secondly, the bits "overflowing" are moved to the next byte. You can see this in the
        // third byte above. 0b_0000_0100 becomes 0b_1000_0010 where the left-most 1 has overflowed
        // from the second byte.
        //
        // Finally, the left-most bit of each blob in `expected` must be 0. You can see this in
        // the second blob of `expected` 0b_0111_0110. Note that the leftmost 1 overflowed from
        // the previous byte (the last row of the example above).

        #[rustfmt::skip] // it's "easier" to read 4 by 4 bytes
            let input = [
            0b_1111_0000, 0b_0011_0101, 0b_0000_0100, 0b_1010_1111,
            0b_1101_1011, 0b_0011_0000, 0b_1001_1011, 0b_0000_1100,
            0b_0101_1101, 0b_1011_1000, 0b_0011_1001, 0b_0111_0101,
            0b_0111_1010, 0b_1011_1111, 0b_1100_1110, 0b_1100_0010,
            0b_0100_0001, 0b_1000_1001, 0b_1101_0001, 0b_0001_1111,
            0b_1110_0000, 0b_0110_0110, 0b_0011_1101, 0b_1011_1011,
            0b_0111_0100, 0b_0000_1110, 0b_0100_0110, 0b_0101_1111,
            0b_0000_0010, ];
        let expected: Vec<Vec<u8>> = vec![
            vec![0b_0111_1000, 0b_0001_1010, 0b_1000_0010, 0b_0101_0111],
            vec![0b_0111_0110, 0b_1100_1100, 0b_0010_0110, 0b_1100_0011],
            vec![0b_0000_1011, 0b_1011_0111, 0b_0000_0111, 0b_0010_1110],
            vec![0b_0101_0111, 0b_1010_1011, 0b_1111_1100, 0b_1110_1100],
            vec![0b_0001_0010, 0b_0000_1100, 0b_0100_1110, 0b_1000_1000],
            vec![0b_0111_1111, 0b_1000_0001, 0b_1001_1000, 0b_1111_0110],
            vec![0b_0111_0110, 0b_1110_1000, 0b_0001_1100, 0b_1000_1100],
            vec![0b_0101_1111, 0b_0000_0010, 0b_0000_0000, 0b_0000_0000],
        ];
        assert_eq!(expected, get_derivation_path(&input));

        // // leaving this here in case the input must be generated again
        // let p = Principal::from_text("fxlwy-axqgu-ck7wz-qtmgf-3obzo-v5l7t-wcige-5ch7a-my63w-5aoiz-pqe").unwrap();
        // println!("vec![");
        // for byte in p.as_slice() {
        //     print!("{:#010b}, ", byte);
        // }
        // print!("]");
    }
}
