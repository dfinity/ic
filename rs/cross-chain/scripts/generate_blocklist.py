import argparse
import xml.etree.ElementTree as ET

# The following steps need to be carried out to update the blocklist for BTC or ETH.
#
# 1) Download the latest version of the OFAC SDN list from their website:
#  https://sanctionslist.ofac.treas.gov/Home/SdnList
#
# Specifically, download the file
#
# SDN_XML.ZIP
#
# and decompress it to retrieve the file 'SDN.XML'.
#
# 2) Run this script as follows:
#
# python generate_blocklist.py --currency {BTC, ETH} --input [path to the SDN.XML file]
#
# The command will generate the file 'blocklist.rs' containing the retrieved addresses.
#
# 3) Override the current 'blocklist.rs' file with the newly generated file.


# The ID type prefix for digital currencies.
DIGITAL_CURRENCY_TYPE_PREFIX = "Digital Currency Address - "

# The blocked addresses are stored in this Rust file by default.
DEFAULT_BLOCKLIST_FILENAME = "blocklist.rs"

# This prefix is needed for each element in the XML tree.
PREFIX = "{https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML}"


# Handlers for different blocklists.
class BitcoinBlocklistHandler:
    def preamble(self):
        return """//! The script to generate this file, including information about the source data, can be found here:
//! /rs/cross-chain/scripts/generate_blocklist.py

#[cfg(test)]
mod tests;

use bitcoin::Address;

/// BTC is not accepted from nor sent to addresses on this list.
/// NOTE: Keep it sorted!
pub const BTC_ADDRESS_BLOCKLIST: &[&str] = &[\n"""

    def postamble(self):
        return """pub fn is_blocked(address: &Address) -> bool {
    BTC_ADDRESS_BLOCKLIST
        .binary_search(&address.to_string().as_ref())
        .is_ok()
}
"""

    def format_address(self, address):
        return f'"{address}"'

    def currency_symbol(self):
        return "XBT"

    def sort(self, addresses):
        return sorted(addresses)


class EthereumBlocklistHandler:
    def preamble(self):
        return """//! The script to generate this file, including information about the source data, can be found here:
//! /rs/cross-chain/scripts/generate_blocklist.py

#[cfg(test)]
mod tests;

use ic_ethereum_types::Address;

macro_rules! ethereum_address {
    ($address:expr_2021) => {
        Address::new(hex_literal::hex!($address))
    };
}

/// ETH is not accepted from nor sent to addresses on this list.
/// NOTE: Keep it sorted!
const ETH_ADDRESS_BLOCKLIST: &[Address] = &[\n"""

    def postamble(self):
        return """pub fn is_blocked(address: &Address) -> bool {
    ETH_ADDRESS_BLOCKLIST.binary_search(address).is_ok()
}

pub const SAMPLE_BLOCKED_ADDRESS: Address = ETH_ADDRESS_BLOCKLIST[0];
"""

    def format_address(self, address):
        return f'ethereum_address!("{address[2:]}")'

    def currency_symbol(self):
        return "ETH"

    def sort(self, addresses):
        return sorted(addresses, key=lambda x: int(x[2:], 16))


def extract_addresses(handler, xml_file_path):
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    addresses = []

    # Iterate over all ID elements.
    for id_item in root.findall(PREFIX + "sdnEntry/" + PREFIX + "idList" + "/" + PREFIX + "id"):
        # Put the ID components into a dictionary for simpler handling.
        id_dict = {}
        for sub_item in id_item:
            if sub_item.text.strip():
                id_dict[sub_item.tag] = sub_item.text

        # Read the address, if any.
        if id_dict[PREFIX + "idType"] == DIGITAL_CURRENCY_TYPE_PREFIX + handler.currency_symbol():
            address = id_dict[PREFIX + "idNumber"]
            addresses.append(address)

    # Remove duplicates.
    addresses = list(set(addresses))
    # Sort the addresses.
    addresses = handler.sort(addresses)
    return addresses


def store_blocklist(blocklist_handler, addresses, filename):
    blocklist_file = open(filename, "w")
    blocklist_file.write(blocklist_handler.preamble())
    for address in addresses:
        blocklist_file.write("    " + blocklist_handler.format_address(address) + ",\n")
        print(address)
    blocklist_file.write("];\n\n")
    blocklist_file.write(blocklist_handler.postamble())
    blocklist_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--currency", "-c", type=str, required=True, choices=["BTC", "ETH"], help="select the currency")
    parser.add_argument("--input", "-i", type=str, required=True, help="read the provided SDN.XML file")
    parser.add_argument(
        "--output", "-o", type=str, default=DEFAULT_BLOCKLIST_FILENAME, help="write the output to the provided path"
    )

    args = parser.parse_args()

    if args.currency == "BTC":
        blocklist_handler = BitcoinBlocklistHandler()
    else:
        blocklist_handler = EthereumBlocklistHandler()
    print("Extracting addresses from " + args.input + "...")
    addresses = extract_addresses(blocklist_handler, args.input)
    print("Done. Found " + str(len(addresses)) + " addresses.")
    print("Storing the addresses in the file " + args.output + "...")
    store_blocklist(blocklist_handler, addresses, args.output)
    print("Done.")
