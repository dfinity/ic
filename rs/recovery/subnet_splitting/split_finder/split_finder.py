#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path

import pulp
from data_io import load_subnet_data
from solver_core import LoadConstraints, solve_partition

DEFAULT_EPSILON_LOAD_DEFAULT = 0.05
DEFAULT_MAX_CUTS = 20
LOAD_TYPES = [
    "instructions_executed",
    "ingress_messages_executed",
    "remote_subnet_messages_executed",
    "local_subnet_messages_executed",
    "http_outcalls_executed",
    "heartbeats_and_global_timers_executed",
]


def compute_max_allowed_load_per_subnet(canister_loads):
    if len(canister_loads) == 0:
        raise ValueError("The provided load data is empty")

    total_canister_loads = sum(canister_loads)
    max_canister_load = max(canister_loads)
    average_load = total_canister_loads / 2
    # If there is a single canister which has is responsible for majority of the load on the subnet
    # it will be impossible to split the subnet in such a way that the load is balanced equally
    # across both of the post-split subnets. In that case we relax the constraints a bit.
    max_allowed_load = max(max_canister_load, average_load)
    return max_allowed_load


def find_split(
    path: Path, baseline_path: Path, communication_data_path: Path, load_type: str, epsilon_load: float, max_cuts: int
):
    data = load_subnet_data(path, baseline_path, load_type, communication_data_path)
    edges = data["edges"]
    load = data["load"]
    index_to_canister_id = data["index_to_canister_id"]

    max_allowed_load_per_subnet = compute_max_allowed_load_per_subnet(load)

    result = solve_partition(
        [LoadConstraints(load_type, load, max_allowed_load_per_subnet, epsilon_load)],
        edges,
        max_cuts,
    )

    problem = result["problem"]
    assignments = result["assignments"]

    if problem.status != pulp.LpStatusOptimal:
        raise RuntimeError("Status: Solution Not Optimal. Please check model constraints and settings.")

    ranges = []
    first_in_range = None
    last_in_range = None
    for k in range(len(assignments)):
        is_to_be_migrated = assignments[k] == 1

        if is_to_be_migrated:
            if first_in_range is not None and last_in_range is not None:
                ranges.append((first_in_range, last_in_range))
            first_in_range, last_in_range = None, None
        else:
            canister_id = index_to_canister_id[k]
            last_in_range = canister_id
            if first_in_range is None:
                first_in_range = canister_id

    if first_in_range is not None and last_in_range is not None:
        ranges.append((first_in_range, last_in_range))

    return ranges


def parse_args():
    parser = argparse.ArgumentParser(description="Run subnet splitting MILP.")
    parser.add_argument("--load-path", type=Path, help="Path to load data", required=True)
    parser.add_argument(
        "--load-baseline-path",
        type=Path,
        help="Path to load baseline data. "
        "It should represent the snapshot of data taken before the data under `load-path` "
        "so that the relative change in the metrics could be computed",
        required=True,
    )
    parser.add_argument(
        "--communication-data-path", type=Path, help="Path to canister-to-canister communication data", required=True
    )
    parser.add_argument(
        "--output-path",
        type=Path,
        help="Path to output data which will contain the list of canister ranges. "
        "It's up to the user to decide whether these canisters should stay on the source subnet or be migrated. "
        "From this script's point of view the decision is symmetric.",
        required=True,
    )
    parser.add_argument(
        "--load-type",
        type=str,
        help="Type of load to optimize for",
        choices=LOAD_TYPES,
        required=True,
    )
    parser.add_argument(
        "--epsilon-load",
        type=float,
        default=DEFAULT_EPSILON_LOAD_DEFAULT,
        help="Allowed load deviation fraction",
    )
    parser.add_argument("--max-cuts", type=int, default=DEFAULT_MAX_CUTS, help="Maximum number of routing cuts")
    return parser.parse_args()


def main():
    args = parse_args()

    canister_ranges = find_split(
        path=args.load_path,
        baseline_path=args.load_baseline_path,
        communication_data_path=args.communication_data_path,
        load_type=args.load_type,
        epsilon_load=args.epsilon_load,
        max_cuts=args.max_cuts,
    )

    with open(args.output_path, "w") as output_file:
        for first_in_range, last_in_range in canister_ranges:
            output_file.write(f"{first_in_range}:{last_in_range}\n")


if __name__ == "__main__":
    main()
