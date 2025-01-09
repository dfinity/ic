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
# and decompress it, which creates the folder 'sdn_xml' containing the file 'SDN.XML'.
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

def store_blocklist(currency, addresses):
    blocklist_file = open(BLOCKLIST_FILENAME, 'w')
    blocklist_file.write('/// '+ currency + ' is not accepted from nor sent to addresses on this list.\n')
    blocklist_file.write('/// The script to generate this file, including information about the source data, can be found here:\n')
    blocklist_file.write('/// /rs/cross-chain/scripts/generate_blocklist.py\n\n')
    blocklist_file.write('/// NOTE: Keep it sorted!\n')
    blocklist_file.write('pub const ' + currency + '_ADDRESS_BLOCKLIST: &[&str] = &[\n')
    for address in addresses:
        blocklist_file.write('\t"' + address + '",\n')
        print(address)
    blocklist_file.write(']+\n\n')
    blocklist_file.write('pub fn is_blocked(from_address: &Address) -> bool {\n')
    blocklist_file.write('    ' + currency + '_ADDRESS_BLOCKLIST.binary_search(from_address).is_ok()\n')
    blocklist_file.write('}')
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
