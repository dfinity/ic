import sys
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
# python generate_blocklist.py [currency (BTC or ETH)] [path to the SDN.XML file]
#
# The command will generate the file 'blocklist.rs' containing the retrieved addresses.
#
# 3) Override the current 'blocklist.rs' file with the newly generated file.


# The ID type prefix for digital currencies.
DIGITAL_CURRENCY_TYPE_PREFIX = 'Digital Currency Address - '

# The blocked addresses are stored in this Rust file.
BLOCKLIST_FILENAME = 'blocklist.rs'

# Invalid addresses in the OFAC SDN list to be commented out.
INVALID_ADDRESSES = ['TUCsTq7TofTCJRRoHk6RvhMoS2mJLm5Yzq']

# This prefix is needed for each element in the XML tree.
PREFIX = '{https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML}'

def extract_addresses(currency, xml_file_path):
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    addresses = []

    # Generate the currency-specific suffix.
    currency_suffix = 'XBT' if currency == 'BTC' else 'ETH'

    # Iterate over all ID elements.
    for id_item in root.findall(PREFIX + 'sdnEntry/' + PREFIX + 'idList' + '/' + PREFIX + 'id'):
        # Put the ID components into a dictionary for simpler handling.
        id_dict = {}
        for sub_item in id_item:
            if sub_item.text.strip():
                id_dict[sub_item.tag] = sub_item.text

        # Read the address, if any.
        if id_dict[PREFIX + 'idType'] == DIGITAL_CURRENCY_TYPE_PREFIX + currency_suffix:
            address = id_dict[PREFIX + 'idNumber']
            addresses.append(address)

    # Remove duplicates.
    addresses = list(set(addresses))
    # Sort the addresses.
    addresses.sort()
    return addresses

def write_btc_preamble(blocklist_file):
    blocklist_file.write('#[cfg(test)]\nmod tests;\n\nuse bitcoin::Address;\n\n')
    blocklist_file.write('/// The script to generate this file, including information about the source data, can be found here:\n')
    blocklist_file.write('/// /rs/cross-chain/scripts/generate_blocklist.py\n\n')
    blocklist_file.write('/// BTC is not accepted from nor sent to addresses on this list.\n')
    blocklist_file.write('/// NOTE: Keep it sorted!\n')
    blocklist_file.write('pub const BTC_ADDRESS_BLOCKLIST: &[&str] = &[\n')

def write_eth_preamble(blocklist_file):
    blocklist_file.write('#[cfg(test)]\nmod tests;\n\nuse ic_ethereum_types::Address;\n\n')
    blocklist_file.write('macro_rules! ethereum_address {\n    ($address:expr) => {\n        Address::new(hex_literal::hex!($address))\n    };\n}\n\n')
    blocklist_file.write('/// The script to generate this file, including information about the source data, can be found here:\n')
    blocklist_file.write('/// /rs/cross-chain/scripts/generate_blocklist.py\n\n')
    blocklist_file.write('/// ETH is not accepted from nor sent to addresses on this list.\n')
    blocklist_file.write('/// NOTE: Keep it sorted!\n')
    blocklist_file.write('const ETH_ADDRESS_BLOCKLIST: &[Address] = &[\n')

def write_btc_postamble(blocklist_file):
    blocklist_file.write('pub fn is_blocked(address: &Address) -> bool {\n')
    blocklist_file.write('    ' + 'BTC_ADDRESS_BLOCKLIST\n        .binary_search(&address.to_string().as_ref())\n        .is_ok()\n')
    blocklist_file.write('}')
    
def write_eth_postamble(blocklist_file):
    blocklist_file.write('pub fn is_blocked(address: &Address) -> bool {\n')
    blocklist_file.write('    ' + 'ETH_ADDRESS_BLOCKLIST.binary_search(address).is_ok()\n')
    blocklist_file.write('}')

def store_blocklist(currency, addresses):
    blocklist_file = open(BLOCKLIST_FILENAME, 'w')
    
    if currency == 'BTC':
        write_btc_preamble(blocklist_file)
        address_prefix = ''
        address_suffix = ''
        offset = 0
    else:   # currency == 'ETH'
        write_eth_preamble(blocklist_file)
        address_prefix = 'ethereum_address!('
        address_suffix = ')'
        offset = 2
    for address in addresses:
        # Ethereum addresses are case-insensitive. By contrast, only Bech32 Bitcoin addresses are case-insensitive.
        if currency == 'ETH':
            address = address.lower()
        if address in INVALID_ADDRESSES:
            blocklist_file.write('    // ' + address_prefix + '"' + address[offset:] + '"' + address_suffix + ' (Invalid address prefix)\n')
            print('Invalid address:', address)
        else:
            blocklist_file.write('    ' + address_prefix + '"' + address[offset:] + '"' + address_suffix + ',\n')
            print(address)
    blocklist_file.write('];\n\n')
    
    if currency == 'BTC':
        write_btc_postamble(blocklist_file)
    else:
        write_eth_postamble(blocklist_file)
    
    blocklist_file.close()

if __name__ == '__main__':  
    if len(sys.argv) < 3:
        print('Usage: ' + sys.argv[0] + ' [currency (BTC or ETH)] [path to SDN.XML file]')
    else:
        currency = sys.argv[1].upper()
        if currency not in ['BTC', 'ETH']:
            print('Error: The currency must be BTC or ETH.')
        else:
            file_path = sys.argv[2]
            print('Extracting addresses from ' + file_path + '...')
            addresses = extract_addresses(currency, file_path)
            print('Done. Found ' + str(len(addresses)) + ' addresses.')
            print('Storing the addresses in the file ' + BLOCKLIST_FILENAME + '...')
            store_blocklist(currency, addresses)
            print('Done.')
