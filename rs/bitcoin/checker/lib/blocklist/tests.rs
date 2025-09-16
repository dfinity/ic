use crate::blocklist::BTC_ADDRESS_BLOCKLIST;
use bitcoin::{Address, Network};
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
