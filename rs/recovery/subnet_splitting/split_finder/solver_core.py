from typing import Dict, List, Tuple

import pulp


def solve_partition(
    load_c: List[float],
    edges: List[Tuple[int, int, float]],
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
    N_c = len(load_c)
    prob = pulp.LpProblem("CanisterSubgroupAssignment", pulp.LpMinimize)

    t = pulp.LpVariable.dicts("t", range(N_c), cat=pulp.LpBinary)
    transitions = pulp.LpVariable.dicts("transition", range(N_c - 1), cat=pulp.LpBinary)

    prob += pulp.lpSum([transitions[i] for i in range(N_c - 1)]) <= max_cuts, "MaxCuts"

    for i in range(N_c - 1):
        prob += transitions[i] >= t[i] - t[i + 1], f"TransitionLower1_{i}"
        prob += transitions[i] >= t[i + 1] - t[i], f"TransitionLower2_{i}"
        prob += transitions[i] <= t[i] + t[i + 1], f"TransitionUpper1_{i}"
        prob += transitions[i] <= 2 - t[i] - t[i + 1], f"TransitionUpper2_{i}"

    z = {}
    for i, j, weight in edges:
        z[(i, j)] = pulp.LpVariable(f"z_{i}_{j}", cat="Binary")
        prob += z[(i, j)] >= t[i] - t[j], f"InterGroupCommLower1_{i}_{j}"
        prob += z[(i, j)] >= t[j] - t[i], f"InterGroupCommLower2_{i}_{j}"
        prob += z[(i, j)] <= t[i] + t[j], f"InterGroupCommUpper1_{i}_{j}"
        prob += z[(i, j)] <= 2 - t[i] - t[j], f"InterGroupCommUpper2_{i}_{j}"

    prob += pulp.lpSum([count * z[(i, j)] for i, j, count in edges]), "TotalInterGroupCommunication"

    load_0 = pulp.lpSum([load_c[k] * (1 - t[k]) for k in range(N_c)])
    load_1 = pulp.lpSum([load_c[k] * t[k] for k in range(N_c)])

    prob += load_0 >= target_load_0 * (1 - epsilon), "LoadBalanceLower_0"
    prob += load_0 <= target_load_0 * (1 + epsilon), "LoadBalanceUpper_0"
    prob += load_1 >= target_load_1 * (1 - epsilon), "LoadBalanceLower_1"
    prob += load_1 <= target_load_1 * (1 + epsilon), "LoadBalanceUpper_1"

    load_sec_0 = load_sec_1 = None
    if (
        load_secondary is not None
        and target_sec_0 is not None
        and target_sec_1 is not None
        and epsilon_secondary is not None
    ):
        load_sec_0 = pulp.lpSum([load_secondary[k] * (1 - t[k]) for k in range(N_c)])
        load_sec_1 = pulp.lpSum([load_secondary[k] * t[k] for k in range(N_c)])
        prob += load_sec_0 >= target_sec_0 * (1 - epsilon_secondary), "LoadSecBalanceLower_0"
        prob += load_sec_0 <= target_sec_0 * (1 + epsilon_secondary), "LoadSecBalanceUpper_0"
        prob += load_sec_1 >= target_sec_1 * (1 - epsilon_secondary), "LoadSecBalanceLower_1"
        prob += load_sec_1 <= target_sec_1 * (1 + epsilon_secondary), "LoadSecBalanceUpper_1"

    solver = pulp.PULP_CBC_CMD(msg=False)
    prob.solve(solver)

    assignments = [int(pulp.value(t[k])) for k in range(N_c)]
    total_transitions = sum(pulp.value(transitions[i]) for i in range(N_c - 1))
    load_sec_0_value = pulp.value(load_sec_0) if load_sec_0 is not None else None
    load_sec_1_value = pulp.value(load_sec_1) if load_sec_1 is not None else None

    return {
        "prob": prob,
        "assignments": assignments,
        "load_0_value": pulp.value(load_0),
        "load_1_value": pulp.value(load_1),
        "load_sec_0_value": load_sec_0_value,
        "load_sec_1_value": load_sec_1_value,
        "total_transitions": total_transitions,
        "objective_value": pulp.value(prob.objective),
        "status": prob.status,
    }
