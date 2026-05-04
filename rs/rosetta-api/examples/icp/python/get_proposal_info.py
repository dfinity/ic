#!/usr/bin/env python3
"""
Get Proposal Info Example

This script demonstrates how to fetch detailed information about a specific proposal
on the Internet Computer Network Nervous System (NNS) using the Rosetta API.

The script retrieves comprehensive information about a proposal, including its
status, voting results, proposer, creation time, execution time, and full proposal
details.

Examples:
    # Get information for proposal ID 123456
    python3 get_proposal_info.py --node-address http://localhost:8081 --proposal-id 123456

    # With raw JSON output
    python3 get_proposal_info.py --node-address http://localhost:8081 --proposal-id 123456 --raw

    # With verbose output
    python3 get_proposal_info.py --node-address http://localhost:8081 --proposal-id 123456 --verbose

"""

import argparse
import json
from datetime import datetime

from rosetta_client import RosettaClient


def format_timestamp(timestamp):
    """Format a Unix timestamp to a human-readable string"""
    if not timestamp:
        return "N/A"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def main():
    parser = argparse.ArgumentParser(description="Get detailed information about a specific proposal on the IC NNS")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--proposal-id", type=int, required=True, help="ID of the proposal to retrieve")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")

    args = parser.parse_args()

    client = RosettaClient(args.node_address)

    print(f"Fetching information for proposal ID: {args.proposal_id}")
    response = client.get_proposal_info(args.proposal_id, verbose=args.verbose)

    if args.raw:
        print(json.dumps(response, indent=2))
        return

    # Extract and display proposal information
    if "result" in response and "proposal" in response["result"]:
        proposal = response["result"]["proposal"]

        # Basic proposal information
        proposal_id = proposal.get("id", "Unknown")
        proposal_type = proposal.get("type", "Unknown")
        proposer = proposal.get("proposer", "Unknown")
        status = proposal.get("status", "Unknown")

        # Times
        created_time = proposal.get("created_timestamp_seconds", 0)
        deadline_time = proposal.get("deadline_timestamp_seconds", 0)
        executed_time = proposal.get("executed_timestamp_seconds", 0)

        # Vote information
        tally = proposal.get("tally", {})
        yes_votes = tally.get("yes", 0)
        no_votes = tally.get("no", 0)
        total_votes = yes_votes + no_votes
        yes_percentage = (yes_votes / total_votes * 100) if total_votes > 0 else 0

        # Display the results
        print("\n=== Proposal Details ===")
        print(f"ID: {proposal_id}")
        print(f"Type: {proposal_type}")
        print(f"Proposer: {proposer}")
        print(f"Status: {status}")
        print(f"Created: {format_timestamp(created_time)}")
        print(f"Deadline: {format_timestamp(deadline_time)}")

        if executed_time:
            print(f"Executed: {format_timestamp(executed_time)}")

        print("\n--- Voting Summary ---")
        print(f"Yes votes: {yes_votes} ({yes_percentage:.2f}%)")
        print(f"No votes: {no_votes} ({100-yes_percentage:.2f}%)")
        print(f"Total votes: {total_votes}")

        # Display summary if available
        if "summary" in proposal:
            print(f"\nSummary: {proposal['summary']}")

        # Display action/payload if available
        if "action" in proposal:
            print("\n--- Proposal Action ---")
            print(json.dumps(proposal["action"], indent=2))
    else:
        print(f"Error: Could not find proposal with ID {args.proposal_id}")


if __name__ == "__main__":
    main()
