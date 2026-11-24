use crate::blocklist::{BTC_ADDRESS_BLOCKLIST, is_blocked};
use bitcoin::{Address, Network, ScriptBuf, ScriptHash, WPubkeyHash, hashes::Hash};
use std::str::FromStr;

#[test]
fn should_be_valid_bitcoin_address_in_canonical_format() {
    for address in BTC_ADDRESS_BLOCKLIST {
        let parsed_address = Address::from_str(address)
            .unwrap_or_else(|e| panic!("BUG: invalid bitcoin address '{address}', error '{e}'"))
            .require_network(Network::Bitcoin)
            .unwrap_or_else(|e| {
                panic!("BUG: invalid address '{address}' for Mainnet Bitcoin, error '{e}'")
            });

        assert_eq!(address, &parsed_address.to_string())
    }
}

#[test]
fn blocklist_is_sorted() {
    for (l, r) in BTC_ADDRESS_BLOCKLIST
        .iter()
        .zip(BTC_ADDRESS_BLOCKLIST.iter().skip(1))
    {
        assert!(l < r, "the block list is not sorted: {l} >= {r}");
    }
}

#[test]
fn should_block_exactly_the_listed_addresses() {
    let parse = |address: &str, network| {
        Address::from_str(address)
            .unwrap()
            .require_network(network)
            .unwrap()
    };

    for address in BTC_ADDRESS_BLOCKLIST {
        assert!(is_blocked(&parse(address, Network::Bitcoin)), "{address}");
    }

    // Addresses that are not on the list, including the addresses of the same hashes of the
    // first P2PKH entry under another network or address type.
    let first_p2pkh = parse(BTC_ADDRESS_BLOCKLIST[0], Network::Bitcoin);
    let pubkey_hash = first_p2pkh
        .pubkey_hash()
        .expect("BUG: expected a P2PKH address");
    let hash = pubkey_hash.to_byte_array();
    let p2wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(hash));
    for address in [
        Address::p2pkh(pubkey_hash, Network::Testnet),
        Address::p2sh_from_hash(ScriptHash::from_byte_array(hash), Network::Bitcoin),
        Address::from_script(&p2wpkh, Network::Bitcoin).unwrap(),
    ] {
        let listed = BTC_ADDRESS_BLOCKLIST.contains(&address.to_string().as_str());
        assert_eq!(is_blocked(&address), listed, "{address}");
    }
}
