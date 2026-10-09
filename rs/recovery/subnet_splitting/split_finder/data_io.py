from pathlib import Path
from typing import Dict, Tuple

import pandas as pd


def load_subnet_data(
    load_path: Path,
    load_baseline_path: Path,
    load_type: str,
    communication_data_path: Path,
    communication_baseline_data_path: Path,
) -> Dict:
    """
    Load canister metadata and communication edges for a subnet.
    Returns a mapping between canister edges and their weights: (i, j) => weight, load vector,
    and index mappings.

    Arguments:
    load_path -- path to a file in the csv format which contains load metrics for each canister.
                 see `rs/state_tool/src/commands/canister_metrics.rs` for how the data is generated
                 and `../test_data/fake_load_sample.csv` for an example.
    load_baseline_path -- path to a file in the in the same format as `load_path`. Represents a
                          sample collected at earlier time. Used to compute relative metrics.
    load_type -- which kind of load (e.g. instructions executed, ingress messages ingested) we want
                 to balance for.
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
    communication_data = communication_data[known_canisters]

    edges: Dict[Tuple[int, int], int] = {}
    for _, row in communication_data.iterrows():
        sender_id = row["sender_canister_id"]
        receiver_id = row["receiver_canister_id"]
        count = row["count"]
        sender_index = canister_id_to_index[sender_id]
        receiver_index = canister_id_to_index[receiver_id]
        edges[(sender_index, receiver_index)] = count

    load = canister_data[load_type].tolist()

    return {
        "edges": edges,
        "load": load,
        "index_to_canister_id": index_to_canister_id,
    }
