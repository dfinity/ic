#!/usr/bin/env python3
"""
ICRC Rosetta API Load Generator

This script generates configurable load against an ICRC Rosetta instance by running
read and write tests at specified rates. It supports:

- Read-only tests: account balance queries, block reads, network info
- Read-write tests: token transfers
- Separate configurable request rates for reads and writes
- High throughput support (up to 20000+ req/s)
- Uniform distribution across canisters and private keys
- Time-limited or indefinite execution
- Real-time statistics and reporting
- Automatic principal tracking from blocks for realistic balance queries

Examples:
    # Run indefinitely with 90 read req/s and 10 write req/s
    python3 load_generator.py \\
        --node-address http://localhost:8082 \\
        --read-canister-ids ryjl3-tyaaa-aaaaa-aaaba-cai \\
        --write-canister-ids ryjl3-tyaaa-aaaaa-aaaba-cai \\
        --private-keys ./key1.pem,./key2.pem \\
        --read-rate 90 \\
        --write-rate 10

    # Run for 60 seconds with 50 read req/s, no writes
    python3 load_generator.py \\
        --node-address http://localhost:8082 \\
        --read-canister-ids canister1,canister2,canister3 \\
        --read-rate 50 \\
        --write-rate 0 \\
        --duration 60

    # High throughput: 15000 read req/s and 5000 write req/s
    python3 load_generator.py \\
        --node-address http://localhost:8082 \\
        --read-canister-ids canister1,canister2 \\
        --write-canister-ids canister3 \\
        --private-keys ./key.pem \\
        --read-rate 15000 \\
        --write-rate 5000
"""

import argparse
import random
import signal
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from rosetta_client import RosettaClient


class LoadGeneratorStats:
    """Thread-safe statistics tracker for load generation"""

    def __init__(self):
        self.lock = threading.Lock()
        self.read_success = 0
        self.read_failure = 0
        self.write_success = 0
        self.write_failure = 0
        self.read_latencies = []
        self.write_latencies = []
        self.start_time = time.time()
        self.operation_counts = defaultdict(int)
        self.error_counts = defaultdict(int)

    def record_read_success(self, latency, operation_type):
        with self.lock:
            self.read_success += 1
            self.read_latencies.append(latency)
            self.operation_counts[operation_type] += 1

    def record_read_failure(self, operation_type, error):
        with self.lock:
            self.read_failure += 1
            self.operation_counts[operation_type] += 1
            error_key = f"{operation_type}:{str(error)[:50]}"
            self.error_counts[error_key] += 1

    def record_write_success(self, latency):
        with self.lock:
            self.write_success += 1
            self.write_latencies.append(latency)
            self.operation_counts["transfer"] += 1

    def record_write_failure(self, error):
        with self.lock:
            self.write_failure += 1
            self.operation_counts["transfer"] += 1
            error_key = f"transfer:{str(error)[:50]}"
            self.error_counts[error_key] += 1

    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            current_time = time.time()
            total_requests = self.read_success + self.read_failure + self.write_success + self.write_failure

            # Calculate average latencies
            avg_read_latency = sum(self.read_latencies) / len(self.read_latencies) if self.read_latencies else 0
            avg_write_latency = sum(self.write_latencies) / len(self.write_latencies) if self.write_latencies else 0

            # Calculate percentiles
            read_p50, read_p95, read_p99 = self._calculate_percentiles(self.read_latencies)
            write_p50, write_p95, write_p99 = self._calculate_percentiles(self.write_latencies)

            return {
                "start_time": self.start_time,
                "current_time": current_time,
                "elapsed": elapsed,
                "total_requests": total_requests,
                "read_success": self.read_success,
                "read_failure": self.read_failure,
                "write_success": self.write_success,
                "write_failure": self.write_failure,
                "avg_read_latency": avg_read_latency,
                "avg_write_latency": avg_write_latency,
                "read_p50": read_p50,
                "read_p95": read_p95,
                "read_p99": read_p99,
                "write_p50": write_p50,
                "write_p95": write_p95,
                "write_p99": write_p99,
                "requests_per_second": total_requests / elapsed if elapsed > 0 else 0,
                "operation_counts": dict(self.operation_counts),
                "error_counts": dict(self.error_counts),
            }

    @staticmethod
    def _calculate_percentiles(latencies):
        if not latencies:
            return 0, 0, 0
        sorted_latencies = sorted(latencies)
        n = len(sorted_latencies)
        p50 = sorted_latencies[int(n * 0.50)]
        p95 = sorted_latencies[int(n * 0.95)] if n > 1 else sorted_latencies[0]
        p99 = sorted_latencies[int(n * 0.99)] if n > 1 else sorted_latencies[0]
        return p50, p95, p99


class LoadGenerator:
    """Main load generator class"""

    # Maximum number of principals to track per canister
    MAX_PRINCIPALS_PER_CANISTER = 1000

    def __init__(
        self,
        node_address,
        read_canister_ids,
        write_canister_ids,
        private_keys,
        read_rate,
        write_rate,
        duration,
        verbose,
    ):
        self.node_address = node_address
        self.read_canister_ids = read_canister_ids
        self.write_canister_ids = write_canister_ids
        self.private_keys = private_keys
        self.read_rate = read_rate
        self.write_rate = write_rate
        self.duration = duration
        self.verbose = verbose
        self.stats = LoadGeneratorStats()
        self.running = True

        # Pre-initialize clients for each canister (to avoid repeated initialization)
        self.read_clients = {}
        self.write_clients = {}

        # Pre-derive principals from private keys
        self.key_principals = {}

        # Track principals seen in blocks per canister (for realistic balance queries)
        # Using deque with maxlen for automatic FIFO eviction
        self.principals_per_canister = {}
        self.principals_lock = threading.Lock()

        # Signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle CTRL+C gracefully"""
        print("\n\nStopping load generator...")
        self.running = False

    def _extract_principals_from_block(self, block_data, canister_id):
        """Extract principals from a block and add them to the tracking deque"""
        try:
            # Extract principals from transactions in the block
            principals = set()
            
            # Check for transactions in the block
            if isinstance(block_data, dict):
                # Look for transaction data
                transaction = block_data.get("transaction", {})
                if transaction:
                    # Extract from operations
                    operations = transaction.get("operations", [])
                    for operation in operations:
                        if isinstance(operation, dict):
                            # Extract account from operation
                            account = operation.get("account", {})
                            if account:
                                address = account.get("address")
                                if address and address != "aaaaa-aa":
                                    principals.add(address)
            
            # Add principals to the per-canister tracking deque
            if principals:
                with self.principals_lock:
                    # Initialize deque for this canister if it doesn't exist
                    if canister_id not in self.principals_per_canister:
                        self.principals_per_canister[canister_id] = deque(maxlen=self.MAX_PRINCIPALS_PER_CANISTER)
                    
                    canister_deque = self.principals_per_canister[canister_id]
                    added_count = 0
                    
                    # Add principals that aren't already in the deque
                    for principal in principals:
                        if principal not in canister_deque:
                            canister_deque.append(principal)
                            added_count += 1
                    
                    if self.verbose and added_count > 0:
                        print(f"Added {added_count} new principal(s) from block for {canister_id} (total: {len(canister_deque)})")
        except Exception as e:
            if self.verbose:
                print(f"Error extracting principals from block: {e}")

    def initialize(self):
        """Initialize clients and derive key information"""
        print("Initializing load generator...")

        # Initialize read clients
        if self.read_canister_ids:
            print(f"Setting up {len(self.read_canister_ids)} read client(s)...")
            for canister_id in self.read_canister_ids:
                try:
                    client = RosettaClient(
                        node_address=self.node_address, canister_id=canister_id, verbose=False
                    )
                    self.read_clients[canister_id] = client
                    print(f"  ✓ Read client for {canister_id}")
                except Exception as e:
                    print(f"  ✗ Failed to initialize read client for {canister_id}: {e}")
                    sys.exit(1)

        # Initialize write clients
        if self.write_canister_ids:
            print(f"Setting up {len(self.write_canister_ids)} write client(s)...")
            for canister_id in self.write_canister_ids:
                try:
                    client = RosettaClient(
                        node_address=self.node_address, canister_id=canister_id, verbose=False
                    )
                    self.write_clients[canister_id] = client
                    print(f"  ✓ Write client for {canister_id}")
                except Exception as e:
                    print(f"  ✗ Failed to initialize write client for {canister_id}: {e}")
                    sys.exit(1)

        # Derive principals from private keys
        if self.private_keys:
            print(f"Deriving principals from {len(self.private_keys)} private key(s)...")
            for key_path in self.private_keys:
                try:
                    key_info = RosettaClient.derive_key_info(private_key_path=key_path, verbose=False)
                    principal = key_info["principal_id"]
                    self.key_principals[key_path] = principal
                    print(f"  ✓ {key_path} -> {principal}")
                except Exception as e:
                    print(f"  ✗ Failed to derive principal from {key_path}: {e}")
                    sys.exit(1)

        print("\nInitialization complete!")

    def run_read_test(self):
        """Execute a random read test"""
        if not self.read_clients:
            return

        # Select a random canister
        canister_id = random.choice(list(self.read_clients.keys()))
        client = self.read_clients[canister_id]

        # Select a random read operation type
        operation = random.choice(["balance", "block", "status"])

        start = time.time()
        try:
            if operation == "balance":
                # Query balance for a random principal from those seen in blocks
                principal = None
                with self.principals_lock:
                    canister_principals = list(self.principals_per_canister.get(canister_id, []))
                
                if canister_principals:
                    # Use a principal seen in blocks for this canister
                    principal = random.choice(canister_principals)
                elif self.key_principals:
                    # Fall back to using one of our key principals
                    principal = random.choice(list(self.key_principals.values()))
                else:
                    # Last resort: use anonymous principal
                    principal = "aaaaa-aa"
                
                client.get_balance(principal=principal, subaccount=None, verbose=False)

            elif operation == "block":
                # Read a random recent block
                status = client.get_status(verbose=False)
                current_height = status.get("current_block_identifier", {}).get("index", 0)
                # Read a block within the last 100 blocks
                block_index = max(0, current_height - random.randint(0, 100))
                block_data = client.get_block(block_index=block_index, block_hash=None, verbose=False)
                
                # Extract principals from the block for future balance queries
                self._extract_principals_from_block(block_data, canister_id)

            elif operation == "status":
                # Get network status
                client.get_status(verbose=False)

            latency = time.time() - start
            self.stats.record_read_success(latency, operation)

        except Exception as e:
            latency = time.time() - start
            self.stats.record_read_failure(operation, str(e))
            if self.verbose:
                print(f"Read test failed ({operation}): {e}")

    def run_write_test(self):
        """Execute a write test (transfer)"""
        if not self.write_clients or not self.private_keys:
            return

        # Select a random canister
        canister_id = random.choice(list(self.write_clients.keys()))
        client = self.write_clients[canister_id]

        # Select a random private key
        private_key_path = random.choice(self.private_keys)
        from_principal = self.key_principals[private_key_path]

        # Select a random recipient (different from sender)
        to_principal_candidates = [p for p in self.key_principals.values() if p != from_principal]
        if not to_principal_candidates:
            # If only one key, use a dummy recipient
            to_principal = "aaaaa-aa"
        else:
            to_principal = random.choice(to_principal_candidates)

        # Use small amounts for load testing (1 unit + fee)
        amount = 10000
        fee = 10000

        start = time.time()
        try:
            client.transfer(
                from_principal=from_principal,
                to_principal=to_principal,
                amount=amount,
                fee=fee,
                private_key_path=private_key_path,
                signature_type="ecdsa",
                from_subaccount=None,
                to_subaccount=None,
                memo=None,
                verbose=False,
            )

            latency = time.time() - start
            self.stats.record_write_success(latency)

        except Exception as e:
            latency = time.time() - start
            self.stats.record_write_failure(str(e))
            if self.verbose:
                print(f"Write test failed: {e}")

    def read_worker(self, num_workers, target_rate):
        """Worker thread that generates read requests"""
        # Calculate inter-request delay based on rate and number of workers
        # Each worker handles a fraction of the total rate
        delay = num_workers / target_rate if target_rate > 0 else 0

        while self.running:
            self.run_read_test()
            time.sleep(delay)

    def write_worker(self, num_workers, target_rate):
        """Worker thread that generates write requests"""
        # Calculate inter-request delay based on rate and number of workers
        # Each worker handles a fraction of the total rate
        delay = num_workers / target_rate if target_rate > 0 else 0

        while self.running:
            self.run_write_test()
            time.sleep(delay)

    def print_stats(self):
        """Print current statistics"""
        stats = self.stats.get_stats()

        # Convert timestamps to UTC datetime strings
        start_time_utc = datetime.utcfromtimestamp(stats['start_time']).strftime('%Y-%m-%d %H:%M:%S UTC')
        current_time_utc = datetime.utcfromtimestamp(stats['current_time']).strftime('%Y-%m-%d %H:%M:%S UTC')

        print("\n" + "=" * 80)
        print(f"Load Generator Statistics (Elapsed: {stats['elapsed']:.1f}s)")
        print("=" * 80)
        print(f"Start Time:         {start_time_utc}")
        print(f"Current Time:       {current_time_utc}")
        print(f"Total Requests:     {stats['total_requests']}")
        print(f"Requests/sec:       {stats['requests_per_second']:.2f}")
        print(f"\nRead Operations:")
        print(f"  Success:          {stats['read_success']}")
        print(f"  Failure:          {stats['read_failure']}")
        if stats["read_success"] > 0:
            print(f"  Avg Latency:      {stats['avg_read_latency'] * 1000:.2f} ms")
            print(
                f"  Latency (p50/p95/p99): {stats['read_p50'] * 1000:.2f} / {stats['read_p95'] * 1000:.2f} / {stats['read_p99'] * 1000:.2f} ms"
            )

        print(f"\nWrite Operations:")
        print(f"  Success:          {stats['write_success']}")
        print(f"  Failure:          {stats['write_failure']}")
        if stats["write_success"] > 0:
            print(f"  Avg Latency:      {stats['avg_write_latency'] * 1000:.2f} ms")
            print(
                f"  Latency (p50/p95/p99): {stats['write_p50'] * 1000:.2f} / {stats['write_p95'] * 1000:.2f} / {stats['write_p99'] * 1000:.2f} ms"
            )

        # Print operation breakdown
        if stats["operation_counts"]:
            print(f"\nOperation Breakdown:")
            for op, count in sorted(stats["operation_counts"].items()):
                print(f"  {op:20s}: {count}")

        # Print tracked principals info
        with self.principals_lock:
            total_principals = sum(len(principals) for principals in self.principals_per_canister.values())
            if total_principals > 0:
                print(f"\nTracked Principals (max {self.MAX_PRINCIPALS_PER_CANISTER} per canister):")
                print(f"  Total:            {total_principals}")
                for canister_id, principals in sorted(self.principals_per_canister.items()):
                    print(f"  {canister_id}: {len(principals)}/{self.MAX_PRINCIPALS_PER_CANISTER}")

        # Print errors if any
        if stats["error_counts"]:
            print(f"\nError Summary (top 5):")
            sorted_errors = sorted(stats["error_counts"].items(), key=lambda x: x[1], reverse=True)
            for error, count in sorted_errors[:5]:
                print(f"  [{count:4d}] {error}")

        print("=" * 80)

    def run(self):
        """Main execution loop"""
        self.initialize()

        # Validate configuration
        if self.write_rate > 0 and (not self.write_clients or not self.private_keys):
            print("Warning: Write rate > 0 but no write canisters or private keys configured")
            print("Only read tests will be executed")
            self.write_rate = 0

        # Calculate total rate
        total_rate = self.read_rate + self.write_rate

        # Print configuration
        print("\n" + "=" * 80)
        print("Load Generator Configuration")
        print("=" * 80)
        print(f"Node Address:       {self.node_address}")
        print(f"Read Canisters:     {len(self.read_canister_ids)} canister(s)")
        print(f"Write Canisters:    {len(self.write_canister_ids)} canister(s)")
        print(f"Private Keys:       {len(self.private_keys)} key(s)")
        print(f"Read Rate:          {self.read_rate} requests/second")
        print(f"Write Rate:         {self.write_rate} requests/second")
        print(f"Total Rate:         {total_rate} requests/second")
        print(
            f"Duration:           {'Indefinite (until CTRL+C)' if self.duration is None else f'{self.duration} seconds'}")
        print("=" * 80)

        # Calculate optimal number of workers for parallelism
        # Use 2x the rate to ensure enough parallelism even with high latency requests
        # Minimum of 2 workers per rate type, maximum of 10000 total to support high throughput
        num_read_workers = int(min(10000, max(2, self.read_rate * 2))) if self.read_rate > 0 else 0
        num_write_workers = int(min(10000, max(2, self.write_rate * 2))) if self.write_rate > 0 else 0
        
        print(f"Read Worker Threads:  {num_read_workers}")
        print(f"Write Worker Threads: {num_write_workers}")
        print(f"Total Worker Threads: {num_read_workers + num_write_workers}")
        print("\nStarting load generation... (Press CTRL+C to stop)\n")

        # Start worker threads
        workers = []
        
        # Start read workers
        for _ in range(num_read_workers):
            t = threading.Thread(target=self.read_worker, args=(num_read_workers, self.read_rate), daemon=True)
            t.start()
            workers.append(t)
        
        # Start write workers
        for _ in range(num_write_workers):
            t = threading.Thread(target=self.write_worker, args=(num_write_workers, self.write_rate), daemon=True)
            t.start()
            workers.append(t)

        # Calculate end time if duration is specified
        end_time = None
        if self.duration is not None:
            end_time = datetime.now() + timedelta(seconds=self.duration)

        # Status update loop
        last_stats_time = time.time()
        stats_interval = 10  # Print stats every 10 seconds

        try:
            while self.running:
                # Check if duration has elapsed
                if end_time is not None and datetime.now() >= end_time:
                    print("\nDuration elapsed. Stopping...")
                    self.running = False
                    break

                # Print stats periodically
                if time.time() - last_stats_time >= stats_interval:
                    self.print_stats()
                    last_stats_time = time.time()

                time.sleep(1)

        except KeyboardInterrupt:
            print("\n\nInterrupted by user...")
            self.running = False

        # Wait for workers to finish
        print("Waiting for workers to finish...")
        for t in workers:
            t.join(timeout=2)

        # Print final statistics
        print("\n\nFinal Statistics:")
        self.print_stats()

        # Calculate success rate
        stats = self.stats.get_stats()
        total_success = stats["read_success"] + stats["write_success"]
        total_requests = stats["total_requests"]
        success_rate = (total_success / total_requests * 100) if total_requests > 0 else 0

        print(f"\nOverall Success Rate: {success_rate:.2f}%")
        print("Load generation complete.")


def parse_comma_separated(value):
    """Parse comma-separated values into a list"""
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def main():
    parser = argparse.ArgumentParser(
        description="ICRC Rosetta API Load Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run indefinitely with 90 read req/s and 10 write req/s
  python3 load_generator.py --node-address http://localhost:8082 \\
      --read-canister-ids ryjl3-tyaaa-aaaaa-aaaba-cai \\
      --write-canister-ids ryjl3-tyaaa-aaaaa-aaaba-cai \\
      --private-keys ./key1.pem,./key2.pem \\
      --read-rate 90 --write-rate 10

  # Run for 60 seconds with 50 read req/s, no writes
  python3 load_generator.py --node-address http://localhost:8082 \\
      --read-canister-ids canister1,canister2,canister3 \\
      --read-rate 50 --write-rate 0 --duration 60

  # High throughput: 15000 read req/s and 5000 write req/s
  python3 load_generator.py --node-address http://localhost:8082 \\
      --read-canister-ids canister1,canister2 \\
      --write-canister-ids canister3 \\
      --private-keys ./key.pem \\
      --read-rate 15000 --write-rate 5000
        """,
    )

    parser.add_argument(
        "--node-address", type=str, required=True, help="Rosetta API endpoint URL (e.g., http://localhost:8082)"
    )

    parser.add_argument(
        "--read-canister-ids",
        type=str,
        help="Comma-separated list of canister IDs for read-only tests (e.g., can1,can2,can3)",
    )

    parser.add_argument(
        "--write-canister-ids",
        type=str,
        help="Comma-separated list of canister IDs for read-write tests (e.g., can1,can2)",
    )

    parser.add_argument(
        "--private-keys",
        type=str,
        help="Comma-separated list of private key file paths for write tests (e.g., key1.pem,key2.pem)",
    )

    parser.add_argument(
        "--read-rate",
        type=float,
        default=0,
        help="Target read request rate in requests per second (e.g., 10, 50, 100, 10000)",
    )

    parser.add_argument(
        "--write-rate",
        type=float,
        default=0,
        help="Target write request rate in requests per second (e.g., 1, 10, 100, 5000)",
    )

    parser.add_argument(
        "--duration",
        type=int,
        help="Duration in seconds to run the test (omit for indefinite, stop with CTRL+C)",
    )

    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for failed requests")

    args = parser.parse_args()

    # Parse comma-separated lists
    read_canister_ids = parse_comma_separated(args.read_canister_ids)
    write_canister_ids = parse_comma_separated(args.write_canister_ids)
    private_keys = parse_comma_separated(args.private_keys)

    # Validation
    if not read_canister_ids and not write_canister_ids:
        print("Error: At least one of --read-canister-ids or --write-canister-ids must be specified")
        sys.exit(1)

    if args.read_rate < 0:
        print("Error: --read-rate must be >= 0")
        sys.exit(1)

    if args.write_rate < 0:
        print("Error: --write-rate must be >= 0")
        sys.exit(1)

    if args.read_rate == 0 and args.write_rate == 0:
        print("Error: At least one of --read-rate or --write-rate must be greater than 0")
        sys.exit(1)

    if args.read_rate > 0 and not read_canister_ids:
        print("Error: --read-canister-ids is required when --read-rate > 0")
        sys.exit(1)

    if args.write_rate > 0 and (not write_canister_ids or not private_keys):
        print("Error: --write-canister-ids and --private-keys are required when --write-rate > 0")
        sys.exit(1)

    if args.duration is not None and args.duration <= 0:
        print("Error: --duration must be greater than 0")
        sys.exit(1)

    # Create and run the load generator
    generator = LoadGenerator(
        node_address=args.node_address,
        read_canister_ids=read_canister_ids,
        write_canister_ids=write_canister_ids,
        private_keys=private_keys,
        read_rate=args.read_rate,
        write_rate=args.write_rate,
        duration=args.duration,
        verbose=args.verbose,
    )

    generator.run()


if __name__ == "__main__":
    main()
