from typing import Dict, List, Tuple

import pulp


def solve_partition(
    load_c: List[float],
    edges: Dict[Tuple[int, int], int],
    target_load_0: float,
    target_load_1: float,
    epsilon: float,
    max_cuts: int,
    load_secondary: List[float] | None = None,
    target_sec_0: float | None = None,
    target_sec_1: float | None = None,
    epsilon_secondary: float | None = None,
) -> Dict:
    """
    Build and solve the MILP for a given load vector and communication edges.
    Optionally enforce a second set of load-balance constraints (e.g., size in
    addition to incoming messages).
    Returns assignments and key metrics to allow testing and reuse.
    """
    canister_count = len(load_c)
    problem = pulp.LpProblem("CanisterSubgroupAssignment", pulp.LpMinimize)

    t = pulp.LpVariable.dicts("t", range(canister_count), cat=pulp.LpBinary)

    z = {}
    # for each pair of consecutive canisters which don't talk to each other, we add an edge of
    # 0 weight, so that we can later add an constraint that the number of pairs of consecutive
    # canisters is bounded
    for i in range(canister_count - 1):
        if (i, i + 1) not in edges:
            edges[(i, i + 1)] = 0

    for (i, j), weight in edges.items():
        z[(i, j)] = pulp.LpVariable(f"z_{i}_{j}", cat="Binary")
        # z[(i, j)] = XOR(t[i], t[j])
        problem += z[(i, j)] >= t[i] - t[j], f"InterGroupCommLower1_{i}_{j}"
        problem += z[(i, j)] >= t[j] - t[i], f"InterGroupCommLower2_{i}_{j}"
        problem += z[(i, j)] <= t[i] + t[j], f"InterGroupCommUpper1_{i}_{j}"
        problem += z[(i, j)] <= 2 - t[i] - t[j], f"InterGroupCommUpper2_{i}_{j}"

    problem += pulp.lpSum([z[(i, i + 1)] for i in range(canister_count - 1)]) <= max_cuts, "MaxCuts"

    problem += pulp.lpSum([count * z[(i, j)] for (i, j), count in edges.items()]), "TotalInterGroupCommunication"

    load_0 = pulp.lpSum([load_c[k] * (1 - t[k]) for k in range(canister_count)])
    load_1 = pulp.lpSum([load_c[k] * t[k] for k in range(canister_count)])

    problem += load_0 >= target_load_0 * (1 - epsilon), "LoadBalanceLower_0"
    problem += load_0 <= target_load_0 * (1 + epsilon), "LoadBalanceUpper_0"
    problem += load_1 >= target_load_1 * (1 - epsilon), "LoadBalanceLower_1"
    problem += load_1 <= target_load_1 * (1 + epsilon), "LoadBalanceUpper_1"

    load_sec_0 = load_sec_1 = None
    if (
        load_secondary is not None
        and target_sec_0 is not None
        and target_sec_1 is not None
        and epsilon_secondary is not None
    ):
        load_sec_0 = pulp.lpSum([load_secondary[k] * (1 - t[k]) for k in range(canister_count)])
        load_sec_1 = pulp.lpSum([load_secondary[k] * t[k] for k in range(canister_count)])
        problem += load_sec_0 >= target_sec_0 * (1 - epsilon_secondary), "LoadSecBalanceLower_0"
        problem += load_sec_0 <= target_sec_0 * (1 + epsilon_secondary), "LoadSecBalanceUpper_0"
        problem += load_sec_1 >= target_sec_1 * (1 - epsilon_secondary), "LoadSecBalanceLower_1"
        problem += load_sec_1 <= target_sec_1 * (1 + epsilon_secondary), "LoadSecBalanceUpper_1"

    solver = pulp.PULP_CBC_CMD(msg=False)
    problem.solve(solver)

    assignments = [int(pulp.value(t[k])) for k in range(canister_count)]

    return {
        "problem": problem,
        "assignments": assignments,
    }
