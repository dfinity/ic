import base64
import zlib
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

# A load type which isn't a column of the load data: every canister contributes one unit of load,
# so balancing it balances the number of canisters on both post-split subnets.
CANISTERS_INSTALLED = "canisters_installed"

# The bytes which end every canister ID, after the 8 bytes of its number.
CANISTER_ID_SUFFIX = b"\x01\x01"


def number_to_canister_id(number: int) -> str:
    """Returns the textual canister ID of the canister with the given number."""
    principal = number.to_bytes(8, "big") + CANISTER_ID_SUFFIX
    checksum = zlib.crc32(principal).to_bytes(4, "big")
    text = base64.b32encode(checksum + principal).decode().rstrip("=").lower()
    return "-".join(text[i : i + 5] for i in range(0, len(text), 5))


def canister_id_to_number(canister_id: str) -> int:
    """Returns the number of the canister with the given textual canister ID."""
    text = canister_id.replace("-", "")
    try:
        principal = base64.b32decode(text + "=" * (-len(text) % 8), casefold=True)[4:]
    except ValueError:
        principal = b""
    if len(principal) != 8 + len(CANISTER_ID_SUFFIX) or not principal.endswith(CANISTER_ID_SUFFIX):
        raise ValueError(f"invalid canister ID: '{canister_id}'")
    number = int.from_bytes(principal[:8], "big")
    # This also rejects a wrong checksum.
    if number_to_canister_id(number) != canister_id:
        raise ValueError(f"invalid canister ID: '{canister_id}'")
    return number


def load_subnet_data(
    load_path: Path,
    load_baseline_path: Path,
    load_types: List[str],
    communication_data_path: Path,
    communication_baseline_data_path: Path,
) -> Dict:
    """
    Load canister metadata and communication edges for a subnet.
    Returns a mapping between canister edges and their weights: (i, j) => weight, a mapping from
    each load type to its load vector, and index mappings.

    Arguments:
    load_path -- path to a file in the csv format which contains load metrics for each canister.
                 see `rs/state_tool/src/commands/canister_metrics.rs` for how the data is generated
                 and `../test_data/fake_load_sample.csv` for an example.
    load_baseline_path -- path to a file in the in the same format as `load_path`. Represents a
                          sample collected at earlier time. Used to compute relative metrics.
    load_types -- which kinds of load (e.g. instructions executed, ingress messages ingested) we
                  want to balance for.
    communication_data_path -- path to a file in the csv format which contains for each pair of
                               canisters, the number of messages they exchanged. See
                               `../test_data/fake_communication_sample.csv` for an example.
    communication_baseline_data_path -- path to a file in the same format as
                                        `communication_data_path`. Represents a sample collected at
                                        an earlier time.

    """
    canister_data = pd.read_csv(load_path).set_index("canister_id")
    canister_baseline_data = pd.read_csv(load_baseline_path).set_index("canister_id")
    canister_data = (
        (canister_data.subtract(canister_baseline_data, fill_value=0)).loc[canister_data.index].reset_index()
    )

    communication_data = pd.read_csv(communication_data_path).set_index(["sender_canister_id", "receiver_canister_id"])
    communication_baseline_data = pd.read_csv(communication_baseline_data_path).set_index(
        ["sender_canister_id", "receiver_canister_id"]
    )
    communication_delta = communication_data.subtract(communication_baseline_data, fill_value=0).loc[
        communication_data.index
    ]
    # A negative delta means that the counter was reset (e.g. evicted and later recreated) since the
    # baseline was collected, so the fresh count is a lower bound on the number of messages
    # exchanged in the meantime. Use it instead of the delta.
    communication_data = communication_delta.where(communication_delta >= 0, communication_data).reset_index()
    canister_data["index"] = range(len(canister_data))
    canister_id_to_index = dict(zip(canister_data["canister_id"], canister_data["index"]))
    index_to_canister_id = dict(zip(canister_data["index"], canister_data["canister_id"]))

    # Ignore communication with canisters which are not in the load data: the connection metrics
    # may still refer to canisters which have since been deleted or migrated away from the subnet.
    known_canisters = communication_data["sender_canister_id"].isin(canister_id_to_index) & communication_data[
        "receiver_canister_id"
    ].isin(canister_id_to_index)
    # Ignore self-edges (a canister calling itself stays co-located under any split) and edges
    # without new messages since the baseline: neither can affect the objective, but each edge
    # still costs the MILP a binary variable and four constraints.
    relevant_edges = (communication_data["sender_canister_id"] != communication_data["receiver_canister_id"]) & (
        communication_data["count"] > 0
    )
    communication_data = communication_data[known_canisters & relevant_edges]

    edges: Dict[Tuple[int, int], int] = {}
    for _, row in communication_data.iterrows():
        sender_id = row["sender_canister_id"]
        receiver_id = row["receiver_canister_id"]
        count = row["count"]
        sender_index = canister_id_to_index[sender_id]
        receiver_index = canister_id_to_index[receiver_id]
        edges[(sender_index, receiver_index)] = count

    loads = {}
    for load_type in load_types:
        if load_type == CANISTERS_INSTALLED:
            # This can't be a constant column of the load data: subtracting the baseline would zero it
            # out for every canister which is present in both samples.
            loads[load_type] = [1] * len(canister_data)
        else:
            loads[load_type] = canister_data[load_type].tolist()

    return {
        "edges": edges,
        "loads": loads,
        "index_to_canister_id": index_to_canister_id,
    }
