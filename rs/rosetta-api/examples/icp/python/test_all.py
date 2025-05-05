#!/usr/bin/env python3
"""
Test All Rosetta API Examples

This script runs all the Rosetta API examples in this directory to verify they work properly.
It also provides a summary of what passed and what failed.

Examples:
    # Basic test of all non-destructive examples (curve type is required)
    python test_all.py --node-address http://localhost:8081 --curve-type edwards25519
    
    # Test all examples including transfers (requires a funded account)
    python test_all.py --node-address http://localhost:8081 \
                       --curve-type edwards25519 \
                       --funded_private_key_pem ./my_private_key.pem \
                       --recipient_account 47e0ae0de8af04a961c4b3225cd77b9652777286ce142c2a07fab98da5263100
                       
    # Test neuron balance example (requires an account ID with neurons)
    python test_all.py --node-address http://localhost:8081 \
                       --curve-type edwards25519 \
                       --public_key_with_neurons 93f14fad36957237baab3b7ce8890c766b44c7071bda09830592379f2a2d418f
"""

import argparse
import subprocess
import sys
import os
import time
from rosetta_client import RosettaClient
import json
import random


class TestResult:
    def __init__(self, script_name, success, output=None, error=None):
        self.script_name = script_name
        self.success = success
        self.output = output
        self.error = error


def run_example(command, script_name, show_output=True):
    """Run an example script and capture its output"""
    print(f"\n[Running] {script_name}")
    print(f"Command: {' '.join(command)}")

    try:
        result = subprocess.run(command,
                                capture_output=True,
                                text=True,
                                check=True)
        print("[Success] ✅")

        if show_output:
            print("\n--- Output ---")
            # Format the output for better readability
            formatted_output = result.stdout.strip()
            if formatted_output:
                print(formatted_output)
            else:
                print("(No output)")
            print("-------------")

        return TestResult(script_name, True, output=result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[Failed] ❌ {e}")

        if show_output and e.stdout:
            print("\n--- Partial Output ---")
            print(e.stdout.strip())
            print("-------------")

        if e.stderr:
            print("\n--- Error Output ---")
            print(e.stderr.strip())
            print("-------------")

        return TestResult(script_name, False, output=e.stdout, error=e.stderr)
    except Exception as e:
        print(f"[Failed] ❌ {e}")
        return TestResult(script_name, False, error=str(e))


def main():
    parser = argparse.ArgumentParser(
        description='Test all Rosetta API examples')
    parser.add_argument("--node-address", type=str,
                        required=True, help="Rosetta node address")
    parser.add_argument("--curve-type", type=str, required=True,
                        help="Curve type for public keys (e.g., edwards25519, secp256k1)")
    parser.add_argument("--funded-private-key-pem", type=str,
                        help="Path to a funded private key PEM file for testing transfers")
    parser.add_argument("--recipient-account", type=str,
                        help="Recipient account ID for testing transfers")
    parser.add_argument("--public-key-with-neurons", type=str,
                        help="Public key with neurons for testing neuron balance")
    parser.add_argument("--verbose", action="store_true",
                        help="Show verbose output")
    parser.add_argument("--no-output", action="store_true",
                        help="Hide command outputs (show only success/failure)")

    args = parser.parse_args()

    # Whether to show command output
    show_output = not args.no_output

    # Track test results
    results = []

    # Common args for all commands
    base_args = ["--node-address", args.node_address]
    if args.verbose:
        base_args.append("--verbose")

    # Test network info
    results.append(run_example(
        ["python", "get_network_info.py"] + base_args,
        "get_network_info.py",
        show_output
    ))

    # Test get account ID (requires a public key)
    # Using a random example public key if not provided
    public_key = args.public_key_with_neurons if args.public_key_with_neurons else "93f14fad36957237baab3b7ce8890c766b44c7071bda09830592379f2a2d418f"
    results.append(run_example(
        ["python", "get_account_id.py"] + base_args +
        ["--public-key", public_key, "--curve-type", args.curve_type],
        "get_account_id.py",
        show_output
    ))

    # Get account identifier for future tests
    try:
        client = RosettaClient(args.node_address)
        account_id = client.get_account_identifier(
            public_key={"hex_bytes": public_key, "curve_type": args.curve_type}
        )
        print(f"\nDerived account ID: {account_id}")
    except Exception as e:
        print(f"Error deriving account ID: {e}")
        # Example fallback
        account_id = "8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4"

    # Test get account balance
    results.append(run_example(
        ["python", "get_account_balance.py"] +
        base_args + ["--account-id", account_id],
        "get_account_balance.py",
        show_output
    ))

    # Test read blocks
    results.append(run_example(
        ["python", "read_blocks.py"] + base_args,
        "read_blocks.py",
        show_output
    ))

    # Test NNS governance examples
    # List known neurons
    results.append(run_example(
        ["python", "list_known_neurons.py"] + base_args,
        "list_known_neurons.py",
        show_output
    ))

    # List pending proposals
    results.append(run_example(
        ["python", "list_pending_proposals.py"] + base_args,
        "list_pending_proposals.py",
        show_output
    ))

    # Get a specific proposal - use a recent one from pending proposals response
    try:
        client = RosettaClient(args.node_address)
        proposals = client.get_pending_proposals()
        if 'result' in proposals and 'pending_proposals' in proposals['result'] and proposals['result']['pending_proposals']:
            proposal_id = proposals['result']['pending_proposals'][0]['id']['id']
            print(f"Testing with proposal ID: {proposal_id}")

            results.append(run_example(
                ["python", "get_proposal_info.py"] + base_args +
                ["--proposal-id", str(proposal_id)],
                "get_proposal_info.py",
                show_output
            ))
        else:
            print("No pending proposals found, skipping get_proposal_info.py test")
    except Exception as e:
        print(f"Error when trying to get a proposal ID: {e}")
        print("Skipping get_proposal_info.py test")

    # Test neuron balance if public key with neurons is provided
    if args.public_key_with_neurons:
        print("\nTesting neuron balance with provided public key")
        results.append(run_example(
            ["python", "get_neuron_balance.py"] + base_args +
            ["--neuron-index", "0", "--public-key",
                args.public_key_with_neurons, "--curve-type", args.curve_type],
            "get_neuron_balance.py",
            show_output
        ))
    else:
        print("\nSkipping neuron balance test (no public key with neurons provided)")

    # Test transfer if funded private key and recipient account are provided
    if args.funded_private_key_pem and args.recipient_account:
        print("\nTesting transfer with provided funded account")
        # Use a very small amount for testing
        amount = 10000  # 0.0001 ICP
        fee = 10000     # Standard fee

        results.append(run_example(
            ["python", "transfer.py"] + base_args +
            ["--private-key-path", args.funded_private_key_pem,
             "--signature-type", "ecdsa",
             "--recipient-account-id", args.recipient_account,
             "--amount-e8s", str(amount),
             "--fee-e8s", str(fee)],
            "transfer.py",
            show_output
        ))
    else:
        print("\nSkipping transfer test (missing funded_private_key_pem and/or recipient_account)")

    # Print summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)

    success_count = sum(1 for r in results if r.success)
    total_count = len(results)

    print(f"Passed: {success_count}/{total_count} tests")

    # Print failures in detail
    failures = [r for r in results if not r.success]
    if failures:
        print("\nFailed Tests:")
        for i, failure in enumerate(failures):
            print(f"{i+1}. {failure.script_name}")
            print(f"   Error: {failure.error}")
            print()

    return 0 if success_count == total_count else 1


if __name__ == "__main__":
    sys.exit(main())
