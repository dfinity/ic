#!/usr/bin/env python3
"""
List Known Neurons Example

This script demonstrates how to list all known neurons on the Internet Computer
Network Nervous System (NNS) using the Rosetta API.

Known neurons are identifiable neurons on the NNS with a name and description,
often controlled by organizations or prominent entities in the Internet Computer
ecosystem.

Examples:
    # Basic usage
    python3 list_known_neurons.py --node-address http://localhost:8081

    # With raw JSON output
    python3 list_known_neurons.py --node-address http://localhost:8081 --raw

    # Sort by ID
    python3 list_known_neurons.py --node-address http://localhost:8081 --sort-by id

    # With verbose output
    python3 list_known_neurons.py --node-address http://localhost:8081 --verbose

"""

import argparse
import json
from datetime import datetime, timedelta

from rosetta_client import RosettaClient


def format_timestamp(timestamp_seconds):
    """Format a Unix timestamp to a human-readable string"""
    if not timestamp_seconds:
        return "N/A"
    return datetime.fromtimestamp(timestamp_seconds).strftime("%Y-%m-%d %H:%M:%S")


def format_duration(seconds):
    """Format a duration in seconds to a human-readable string"""
    if not seconds:
        return "N/A"

    duration = timedelta(seconds=seconds)
    days = duration.days
    hours, remainder = divmod(duration.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    return ", ".join(parts) if parts else f"{seconds} seconds"


def main():
    parser = argparse.ArgumentParser(description="List known neurons on the Internet Computer NNS")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")
    parser.add_argument(
        "--sort-by", type=str, choices=["stake", "age", "id"], default="stake", help="Sort neurons by stake, age, or ID"
    )
    parser.add_argument("--min-stake", type=float, help="Filter neurons with minimum stake (in ICP)")

    args = parser.parse_args()

    client = RosettaClient(args.node_address)

    print("Fetching known neurons from the NNS...")
    response = client.list_known_neurons(verbose=args.verbose)

    if args.raw:
        print(json.dumps(response, indent=2))
        return

    # Extract neurons from the response
    if "result" in response and "known_neurons" in response["result"]:
        known_neurons = response["result"]["known_neurons"]
        print(f"\nFound {len(known_neurons)} known neuron{'s' if len(known_neurons) != 1 else ''}")

        # Convert to more usable format
        neurons = []
        for kn in known_neurons:
            neuron = {}

            # Extract neuron ID
            if "id" in kn and "id" in kn["id"]:
                neuron["id"] = kn["id"]["id"]
            else:
                neuron["id"] = "Unknown"

            # Extract neuron metadata
            if "known_neuron_data" in kn:
                data = kn["known_neuron_data"]
                neuron["name"] = data.get("name", "Unnamed")
                neuron["description"] = data.get("description", "")
                neuron["links"] = data.get("links", []) or []
                neuron["committed_topics"] = data.get("committed_topics", []) or []

            neurons.append(neuron)

        # Apply minimum stake filter if provided
        if args.min_stake is not None:
            print("Note: Stake information not available in known_neurons response, skipping min_stake filter")

        # Sort based on the criteria
        if args.sort_by == "stake":
            print("Note: Stake information not available in known_neurons response, sorting by ID instead")
            neurons.sort(key=lambda n: n.get("id", 0))
        elif args.sort_by == "age":
            print("Note: Age information not available in known_neurons response, sorting by ID instead")
            neurons.sort(key=lambda n: n.get("id", 0))
        elif args.sort_by == "id":
            neurons.sort(key=lambda n: n.get("id", 0))

        for i, neuron in enumerate(neurons):
            neuron_id = neuron.get("id", "Unknown")
            neuron_name = neuron.get("name", "Unnamed")
            neuron_description = neuron.get("description", "")
            neuron_links = neuron.get("links", []) or []
            neuron_committed_topics = neuron.get("committed_topics", []) or []

            print(f"\n--- Neuron {i+1} ---")
            print(f"ID: {neuron_id}")
            print(f"Name: {neuron_name}")

            if neuron_description:
                # Truncate description if too long for display
                max_desc_length = 200
                if len(neuron_description) > max_desc_length:
                    desc_display = neuron_description[:max_desc_length] + "..."
                else:
                    desc_display = neuron_description
                print(f"Description: {desc_display}")

            if len(neuron_links) > 0:
                print("Links:")
                for link in neuron_links:
                    print(f"  - {link}")

            if len(neuron_committed_topics) > 0:
                print("Committed Topics:")
                for topic in neuron_committed_topics:
                    print(f"  - {topic}")
    else:
        print("No known neurons found or unexpected response format. Response structure:")
        print(json.dumps(response, indent=2))


if __name__ == "__main__":
    main()
