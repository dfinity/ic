#!/usr/bin/env python3
r"""
Test All ICRC-1 Rosetta API Examples

This script runs all the ICRC-1 Rosetta API examples in this directory to verify they work properly.
It also provides a summary of what passed and what failed.

Examples:
    # Basic test of non-destructive examples requiring principal ID
    python3 test_all.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id>

    # Test all examples including transfers (requires a funded account)
    python3 test_all.py --node-address http://localhost:8082 \\
                       --canister-id <canister-id> \\
                       --principal-id <principal-id> \\
                       --private-key-path ./my_private_key.pem \\
                       --to-principal <to-principal-id> \\
                       --amount 100 \\
                       --fee 10

"""

import argparse
import subprocess
import sys


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
        result = subprocess.run(command, capture_output=True, text=True, check=True)
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
        description="Test all ICRC-1 Rosetta API examples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic test of read-only operations
  python3 test_all.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id>

  # Complete test including transfers (requires a funded account)
  python3 test_all.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id> \\
                    --private-key-path ./my_private_key.pem --to-principal <recipient-id> --amount 100 --fee 10
        """,
    )
    # Required parameters
    required = parser.add_argument_group("Required parameters")
    required.add_argument(
        "--node-address", type=str, required=True, help="Rosetta node address (e.g., http://localhost:8082)"
    )
    required.add_argument(
        "--canister-id",
        type=str,
        required=True,
        help="Canister ID of the ICRC-1 ledger (e.g., ryjl3-tyaaa-aaaaa-aaaba-cai)",
    )
    required.add_argument(
        "--principal-id", type=str, required=True, help="Principal ID for testing account balance queries"
    )

    # Transfer testing parameters (optional as a group)
    transfer = parser.add_argument_group("Transfer testing parameters (all required to test transfers)")
    transfer.add_argument(
        "--private-key-path",
        type=str,
        help="Path to a private key PEM file for the sender account (the sender principal will be derived from this)",
    )
    transfer.add_argument("--to-principal", type=str, help="To principal ID (recipient's account for the transfer)")
    transfer.add_argument("--amount", type=int, default=100, help="Amount to transfer (default: 100)")
    transfer.add_argument("--fee", type=int, default=10, help="Fee to pay for the transfer (default: 10)")

    # Output control parameters
    output = parser.add_argument_group("Output control")
    output.add_argument("--verbose", action="store_true", help="Enable verbose API request/response output")
    output.add_argument("--no-output", action="store_true", help="Hide command outputs (show only success/failure)")

    args = parser.parse_args()

    # Whether to show command output
    show_output = not args.no_output

    # Track test results
    results = []

    # Common args for all commands
    base_args = ["--node-address", args.node_address, "--canister-id", args.canister_id]
    if args.verbose:
        base_args.append("--verbose")

    # Test network info
    results.append(run_example(["python3", "get_network_info.py"] + base_args, "get_network_info.py", show_output))

    # Test read blocks
    results.append(run_example(["python3", "read_blocks.py"] + base_args, "read_blocks.py", show_output))

    # Test balance query - use the provided principal
    results.append(
        run_example(
            ["python3", "get_account_balance.py"] + base_args + ["--principal-id", args.principal_id],
            "get_account_balance.py",
            show_output,
        )
    )

    # Test aggregated balance query
    results.append(
        run_example(
            ["python3", "get_account_balance.py"] + base_args + ["--principal-id", args.principal_id, "--aggregate"],
            "get_account_balance.py (aggregated)",
            show_output,
        )
    )

    # Test transfer if funded private key and principal IDs are provided
    if args.private_key_path and args.to_principal:
        print("\nTesting transfer with provided funded account")
        amount = args.amount
        fee = args.fee
        print(f"Using amount: {amount}, fee: {fee}")

        results.append(
            run_example(
                ["python3", "transfer.py"]
                + base_args
                + [
                    "--private-key-path",
                    args.private_key_path,
                    "--signature-type",
                    "ecdsa",
                    "--to-principal",
                    args.to_principal,
                    "--amount",
                    str(amount),
                    "--fee",
                    str(fee),
                ],
                "transfer.py",
                show_output,
            )
        )
    else:
        print("\nSkipping transfer test (missing private_key_path and/or to_principal)")

    # Print summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)

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
