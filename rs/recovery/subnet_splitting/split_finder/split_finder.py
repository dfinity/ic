#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import bisect
import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pulp
from data_io import CANISTERS_INSTALLED, canister_id_to_number, load_subnet_data
from solver_core import LoadConstraints, solve_partition

DEFAULT_EPSILON_LOAD_DEFAULT = 0.05
DEFAULT_MAX_CUTS = 20
LOAD_TYPES = [
    CANISTERS_INSTALLED,
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


def assign_canisters_to_ranges(canister_ids: List[str], canister_id_ranges: List[Tuple[str, str]]) -> List[int]:
    """
    Returns, for each canister, the index of the canister ID range which contains it. Adjacent
    ranges are merged into one first.

    Raises a `ValueError` if the canister IDs are not in increasing order, if the ranges overlap, or
    if a canister lies outside all the ranges.
    """
    # The first and last canister numbers of each range, in increasing order.
    ranges = sorted((canister_id_to_number(first), canister_id_to_number(last)) for first, last in canister_id_ranges)
    merged_ranges: List[Tuple[int, int]] = []
    for first, last in ranges:
        if merged_ranges and first <= merged_ranges[-1][1]:
            raise ValueError(f"The canister ID ranges {canister_id_ranges} overlap")
        if merged_ranges and first == merged_ranges[-1][1] + 1:
            merged_ranges[-1] = (merged_ranges[-1][0], last)
        else:
            merged_ranges.append((first, last))
    range_starts = [first for first, _ in merged_ranges]

    range_indices = []
    previous_number = None
    for canister_id in canister_ids:
        number = canister_id_to_number(canister_id)
        if previous_number is not None and number <= previous_number:
            raise ValueError(
                f"The canisters in the load data are not in increasing order of canister ID at {canister_id}"
            )
        previous_number = number
        range_index = bisect.bisect_right(range_starts, number) - 1
        if range_index < 0 or number > merged_ranges[range_index][1]:
            raise ValueError(f"Canister {canister_id} lies outside the canister ID ranges {canister_id_ranges}")
        range_indices.append(range_index)
    return range_indices


def group_into_canister_ranges(
    assignments: List[int], canister_ids: List[str], range_indices: List[int]
) -> List[Tuple[str, str]]:
    """
    Returns the canister ranges, as `(first, last)` canister IDs to be migrated away.

    The canister IDs must be in increasing order, and `range_indices` are the indices of the
    subnet's canister ID ranges which contain them, as returned by `assign_canisters_to_ranges`.
    """
    ranges = []
    first_in_range = None
    last_in_range = None
    for k in range(len(assignments)):
        # A range must not cover the canister IDs between two of the subnet's canister ID ranges,
        # because the routing table assigns them to other subnets. So a range also ends where the
        # subnet's canister ID range does.
        if first_in_range is not None and (assignments[k] == 1 or range_indices[k] != range_indices[k - 1]):
            ranges.append((first_in_range, last_in_range))
            first_in_range = None
        if assignments[k] == 0:
            last_in_range = canister_ids[k]
            if first_in_range is None:
                first_in_range = last_in_range

    if first_in_range is not None:
        ranges.append((first_in_range, last_in_range))

    return ranges


def find_split(
    path: Path,
    baseline_path: Path,
    communication_data_path: Path,
    communication_baseline_data_path: Path,
    subnet_canister_id_ranges: List[Tuple[str, str]],
    load_epsilons: Dict[str, float],
    max_cuts: int,
):
    """
    Find a split which minimizes the communication between both post-split subnets.

    `subnet_canister_id_ranges` are the canister ID ranges which the routing table assigns to the
    subnet, as `(first, last)` canister IDs.

    `load_epsilons` maps each load type to balance to its allowed load deviation fraction: the load
    of either post-split subnet may exceed the maximum allowed load per subnet by that fraction.
    """
    data = load_subnet_data(
        path, baseline_path, list(load_epsilons), communication_data_path, communication_baseline_data_path
    )
    edges = data["edges"]
    loads = data["loads"]
    index_to_canister_id = data["index_to_canister_id"]
    canister_ids = [index_to_canister_id[k] for k in range(len(index_to_canister_id))]
    range_indices = assign_canisters_to_ranges(canister_ids, subnet_canister_id_ranges)

    load_constraints = [
        LoadConstraints(load_type, load, compute_max_allowed_load_per_subnet(load), load_epsilons[load_type])
        for load_type, load in loads.items()
    ]

    result = solve_partition(load_constraints, edges, max_cuts)

    problem = result["problem"]
    assignments = result["assignments"]

    if problem.status != pulp.LpStatusOptimal:
        raise RuntimeError(
            f"Status: {pulp.LpStatus[problem.status]}. No optimal split balances every load type within its "
            f"allowed load deviation {load_epsilons} using at most {max_cuts} cuts. "
            "Consider allowing larger load deviations or more cuts, or balancing fewer load types."
        )

    return group_into_canister_ranges(assignments, canister_ids, range_indices)


def parse_epsilon(value: str) -> float:
    try:
        epsilon = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid load deviation fraction: '{value}'") from None
    if not math.isfinite(epsilon) or epsilon < 0:
        raise argparse.ArgumentTypeError(f"load deviation fraction must be a non-negative number: '{value}'")
    return epsilon


def parse_load_type(value: str) -> Tuple[str, Optional[float]]:
    """Parse a `TYPE[=EPSILON]` argument into the load type and its epsilon, if one is given."""
    load_type, separator, epsilon = value.partition("=")
    if load_type not in LOAD_TYPES:
        raise argparse.ArgumentTypeError(f"invalid load type: '{load_type}' (choose from {', '.join(LOAD_TYPES)})")
    return load_type, parse_epsilon(epsilon) if separator else None


def parse_canister_id_range(value: str) -> Tuple[str, str]:
    """Parse a `START:END` argument into the first and last canister IDs of the range."""
    start, separator, end = value.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError(f"invalid canister ID range: '{value}' (expected START:END)")
    try:
        if canister_id_to_number(start) > canister_id_to_number(end):
            raise argparse.ArgumentTypeError(f"invalid canister ID range: '{value}' (START is greater than END)")
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"invalid canister ID range: '{value}' ({err})") from None
    return start, end


def parse_args(argv=None):
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
        "--communication-baseline-data-path",
        type=Path,
        help="Path to baseline canister-to-canister communication data. "
        "It should represent the snapshot of communication data taken before the data under `communication-data-path` "
        "so that the relative change in the metrics could be computed",
        required=True,
    )
    parser.add_argument(
        "--subnet-canister-id-ranges",
        type=parse_canister_id_range,
        nargs="+",
        metavar="START:END",
        help="All the canister ID ranges which the routing table assigns to the subnet."
        required=True,
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
        dest="load_types",
        type=parse_load_type,
        nargs="+",
        metavar="TYPE[=EPSILON]",
        help="Types of load to balance across both post-split subnets, each with an optional allowed load "
        "deviation fraction which defaults to `--epsilon-load`. The split must balance every one of them. "
        f"Choose from: {', '.join(LOAD_TYPES)}.",
        required=True,
    )
    parser.add_argument(
        "--epsilon-load",
        type=parse_epsilon,
        default=DEFAULT_EPSILON_LOAD_DEFAULT,
        help="Allowed load deviation fraction of the load types which don't specify their own",
    )
    parser.add_argument("--max-cuts", type=int, default=DEFAULT_MAX_CUTS, help="Maximum number of routing cuts")
    args = parser.parse_args(argv)

    args.load_epsilons = {}
    for load_type, epsilon in args.load_types:
        if load_type in args.load_epsilons:
            parser.error(f"argument --load-type: load type '{load_type}' given more than once")
        args.load_epsilons[load_type] = args.epsilon_load if epsilon is None else epsilon

    return args


def main():
    args = parse_args()

    canister_ranges = find_split(
        path=args.load_path,
        baseline_path=args.load_baseline_path,
        communication_data_path=args.communication_data_path,
        communication_baseline_data_path=args.communication_baseline_data_path,
        subnet_canister_id_ranges=args.subnet_canister_id_ranges,
        load_epsilons=args.load_epsilons,
        max_cuts=args.max_cuts,
    )

    with open(args.output_path, "w") as output_file:
        for first_in_range, last_in_range in canister_ranges:
            output_file.write(f"{first_in_range}:{last_in_range}\n")


if __name__ == "__main__":
    main()
