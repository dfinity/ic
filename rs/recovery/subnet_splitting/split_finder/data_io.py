from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

"""
"""


def load_subnet_data(load_path: Path, load_type: str, communication_data_path: Path) -> Dict:
    """
    Load canister metadata and communication edges for a subnet.
    Returns canister DataFrame, edge list (i, j, weight), load vector, and index mappings.

    Arguments:
    load_path -- path to a file in the csv format which contains load metrics for each canister.
                 see `rs/state_tool/src/commands/canister_metrics.rs` for how the data is generated
                 and `../test_data/fake_load_sample.csv` for an example.
    load_type -- which kind of load (e.g. instructions executed, ingress messages ingested) we want
                 to balance for.
    communication_data_path -- path to a file in the csv format which contains for each pair of
                               canisters, the number of messages they exchanged. See
                               `../test_data/fake_communication_sample.csv` for an example.

    """
    canister_data = pd.read_csv(load_path)
    canister_data = canister_data[["canister_id", load_type]]
    canister_data["original_index"] = range(len(canister_data))

    communication_data = pd.read_csv(communication_data_path)
    communication_data = communication_data[["sender_canister_id", "receiver_canister_id", "count"]]

    communicating_canister_ids = set(communication_data["sender_canister_id"]).union(
        set(communication_data["receiver_canister_id"])
    )
    communicating_canisters = canister_data[canister_data["canister_id"].isin(communicating_canister_ids)].reset_index(
        drop=True
    )

    communicating_canisters["index"] = range(len(communicating_canisters))

    canister_id_to_index = dict(zip(communicating_canisters["canister_id"], communicating_canisters["index"]))
    index_to_canister_id = dict(zip(communicating_canisters["index"], communicating_canisters["canister_id"]))

    edges: List[Tuple[int, int, float]] = []
    for _, row in communication_data.iterrows():
        sender_id = row["sender_canister_id"]
        receiver_id = row["receiver_canister_id"]
        count = row["count"]
        if sender_id in canister_id_to_index and receiver_id in canister_id_to_index:
            i = canister_id_to_index[sender_id]
            j = canister_id_to_index[receiver_id]
            edges.append((i, j, count))

    load = communicating_canisters[load_type].tolist()

    return {
        "communicating_canisters": communicating_canisters,
        "edges": edges,
        "load": load,
        "index_to_canister_id": index_to_canister_id,
    }
