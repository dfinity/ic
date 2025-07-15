#!/usr/bin/env python3
"""
Get Minimum Dissolve Delay for Neuron Example

This script demonstrates how to get the minimum dissolve delay of a neuron
that still allows it to vote on NNS proposals.

Examples:
    # Basic usage
    python3 get_minimum_dissolve_delay.py --node-address http://localhost:8081

    # With raw JSON output
    python3 get_minimum_dissolve_delay.py --node-address http://localhost:8081 --raw

    # With verbose output
    python3 get_minimum_dissolve_delay.py --node-address http://localhost:8081 --verbose

"""

import argparse
import json

from rosetta_client import RosettaClient


def main():
    parser = argparse.ArgumentParser(
        description="Get the minimum dissolve delay of a neuron that still allows it to vote."
    )
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")

    args = parser.parse_args()

    client = RosettaClient(args.node_address)

    print("Fetching minimum dissolve delay of a neuron...")
    response = client.get_minimum_dissolve_delay(verbose=args.verbose)

    if args.raw:
        print(json.dumps(response, indent=2))
        return

    # Extract minimum dissolve delay from the response
    if "result" in response and "neuron_minimum_dissolve_delay_to_vote_seconds" in response["result"]:
        dissove_seconds = response["result"]["neuron_minimum_dissolve_delay_to_vote_seconds"]
        print("Neuron minimum dissolve delay to vote in seconds:", dissove_seconds)
    else:
        print("No minimum neuron delay found or unexpected response format")


if __name__ == "__main__":
    main()
