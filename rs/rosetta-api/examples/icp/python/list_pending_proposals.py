#!/usr/bin/env python3
"""
List Pending Proposals Example

This script demonstrates how to list all pending proposals on the Internet Computer
Network Nervous System (NNS) using the Rosetta API.

Proposals are used for governance decisions on the Internet Computer, and this
script shows the titles, descriptions, proposers, voting status, and other details
for all currently pending proposals.

Examples:
    # Basic usage
    python3 list_pending_proposals.py --node-address http://localhost:8081

    # With raw JSON output
    python3 list_pending_proposals.py --node-address http://localhost:8081 --raw

    # With verbose output
    python3 list_pending_proposals.py --node-address http://localhost:8081 --verbose

"""

import argparse
import json
from datetime import datetime

from rosetta_client import RosettaClient


def main():
    parser = argparse.ArgumentParser(description="List pending proposals on the Internet Computer NNS")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")

    args = parser.parse_args()

    client = RosettaClient(args.node_address)

    print("Fetching pending proposals from the NNS...")
    response = client.get_pending_proposals(verbose=args.verbose)

    if args.raw:
        print(json.dumps(response, indent=2))
        return

    # Extract proposals from the response
    if "result" in response and "pending_proposals" in response["result"]:
        proposals = response["result"]["pending_proposals"]
        print(f"\nFound {len(proposals)} pending proposal(s)")

        # Sort proposals by creation time if available
        try:
            proposals.sort(key=lambda p: p.get("created_timestamp_seconds", 0), reverse=True)
        except (KeyError, TypeError):
            pass

        for i, proposal in enumerate(proposals):
            proposal_id = proposal.get("id", {}).get("id", "Unknown ID")

            # Access proposal details from the 'proposal' field if it exists
            proposal_data = proposal.get("proposal", {})
            proposal_type = proposal_data.get("title", "Unknown type")
            proposal_summary = proposal_data.get("summary", "")
            proposer = f"Neuron {proposal.get('proposer', {}).get('id', 'Unknown')}"

            # Format creation time if available
            created_time = proposal.get("proposal_timestamp_seconds", 0)
            created_date = (
                datetime.fromtimestamp(created_time).strftime("%Y-%m-%d %H:%M:%S") if created_time else "Unknown"
            )

            # Format deadline if available
            deadline = proposal.get("deadline_timestamp_seconds", 0)
            deadline_date = (
                datetime.fromtimestamp(deadline).strftime("%Y-%m-%d %H:%M:%S") if deadline else "No deadline"
            )

            print(f"\n--- Proposal {i+1} ---")
            print(f"ID: {proposal_id}")
            print(f"Title: {proposal_type}")
            print(f"Proposer: {proposer}")
            print(f"Created: {created_date}")
            print(f"Deadline: {deadline_date}")

            # Show proposal status if available
            if "status" in proposal:
                status_code = proposal.get("status", 0)
                status_text = {0: "Unknown", 1: "Open", 2: "Accepted", 3: "Rejected", 4: "Executed", 5: "Failed"}.get(
                    status_code, f"Status code: {status_code}"
                )
                print(f"Status: {status_text}")

            # Show topic if available
            if "topic" in proposal:
                topic_code = proposal.get("topic", 0)
                topic_text = {
                    0: "Unspecified",
                    1: "Neuron Management",
                    2: "Exchange Rate",
                    3: "Network Economics",
                    4: "Governance",
                    5: "Node Administration",
                    6: "Participant Management",
                    7: "Subnet Management",
                    8: "Network Canister Management",
                    9: "KYC",
                    10: "Node Provider Rewards",
                    11: "SNS and Community Fund",
                    12: "Subnet ECDSA Keys",
                }.get(topic_code, f"Topic code: {topic_code}")
                print(f"Topic: {topic_text}")

            # Show voting tally if available
            if "latest_tally" in proposal:
                tally = proposal["latest_tally"]
                yes_votes = int(tally.get("yes", 0))
                no_votes = int(tally.get("no", 0))
                total_votes = int(tally.get("total", 0))
                yes_percentage = (yes_votes / total_votes * 100) if total_votes > 0 else 0
                no_percentage = (no_votes / total_votes * 100) if total_votes > 0 else 0

                print(
                    f"Votes: {yes_votes / 10**8:.2f} ICP yes ({yes_percentage:.1f}%), {no_votes / 10**8:.2f} ICP no ({no_percentage:.1f}%)"
                )
                print(f"Total voting power: {total_votes / 10**8:.2f} ICP")

            # Show summary if available (truncated if too long)
            if proposal_summary:
                max_len = 200
                summary_display = (
                    proposal_summary if len(proposal_summary) <= max_len else f"{proposal_summary[:max_len]}..."
                )
                print(f"Summary: {summary_display}")

            # Show URL if available
            if "url" in proposal_data:
                print(f"URL: {proposal_data['url']}")
    else:
        print("No pending proposals found or unexpected response format")


if __name__ == "__main__":
    main()
