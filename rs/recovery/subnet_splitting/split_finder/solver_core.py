from typing import Dict, List, Tuple

import pulp


class LoadConstraints:
    name: str
    canister_loads: List[float]
    max_allowed_load_per_subnet: float
    epsilon: float

    def __init__(self, name, canister_loads, max_allowed_load_per_subnet, epsilon):
        self.name = name
        self.canister_loads = canister_loads
        self.max_allowed_load_per_subnet = max_allowed_load_per_subnet
        self.epsilon = epsilon


def solve_partition(
    load_constraints: List[LoadConstraints],
    edges: Dict[Tuple[int, int], int],
    max_cuts: int,
) -> Dict:
    """
    Build and solve the MILP for a given load vector(s) and communication edges.
    Returns the subnet assignment for each of the canisters.
    """
    if len(load_constraints) == 0:
        raise ValueError("The provided load constraints data is empty")
    if any(
        len(constraint.canister_loads) != len(load_constraints[0].canister_loads) for constraint in load_constraints
    ):
        raise ValueError("All load constraints must have the same number of canisters")
    canister_count = len(load_constraints[0].canister_loads)
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

    for load_constraint in load_constraints:
        load_0 = pulp.lpSum([load_constraint.canister_loads[k] * (1 - t[k]) for k in range(canister_count)])
        load_1 = pulp.lpSum([load_constraint.canister_loads[k] * t[k] for k in range(canister_count)])
        max_allowed_load = load_constraint.max_allowed_load_per_subnet
        epsilon = load_constraint.epsilon
        name = load_constraint.name

        problem += load_0 <= max_allowed_load * (1 + epsilon), f"LoadUpper_0_{name}"
        problem += load_1 <= max_allowed_load * (1 + epsilon), f"LoadUpper_1_{name}"

    solver = pulp.PULP_CBC_CMD(msg=False)
    problem.solve(solver)

    assignments = [int(pulp.value(t[k])) for k in range(canister_count)]

    return {
        "problem": problem,
        "assignments": assignments,
    }
