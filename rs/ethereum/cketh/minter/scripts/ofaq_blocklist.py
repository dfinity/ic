import re

import requests

try:
    response = requests.get("https://www.treasury.gov/ofac/downloads/prgrmlst.txt")

    # Check if the request was successful
    if response.status_code == 200:
        lines = response.text.split("\n")

        # Filter lines containing "Digital Currency Address - ETH" and "0x"
        filtered_lines = [line for line in lines if "Digital Currency Address - ETH" and "0x" in line]

        eth_address_pattern = r'0x[a-fA-F0-9]{40}'
        eth_addresses = [address for address in filtered_lines if re.match(eth_address_pattern, address)]
        unique_eth_addresses = list(set(eth_addresses))

        for line in unique_eth_addresses:
            print(line.split(';')[0])
        print("Found", len(unique_eth_addresses), "addresses in the OFAC SDN list")
    else:
        print("Failed to fetch data. Status code:", response.status_code)

except requests.exceptions.RequestException as e:
    print("An error occurred:", e)
