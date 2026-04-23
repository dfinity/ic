from pathlib import Path
from typing import Dict, Tuple

import pandas as pd


def load_subnet_data(load_path: Path, load_baseline_path: Path, load_type: str, communication_data_path: Path) -> Dict:
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

    """
    canister_data = pd.read_csv(load_path).set_index("canister_id")
    canister_baseline_data = pd.read_csv(load_baseline_path).set_index("canister_id")
    canister_data = (canister_data.subtract(canister_baseline_data, fill_value=0)).loc[canister_data.index]

    canister_data = canister_data.reset_index()[["canister_id", load_type]]

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

    edges: Dict[Tuple[int, int], int] = {}
    for _, row in communication_data.iterrows():
        sender_id = row["sender_canister_id"]
        receiver_id = row["receiver_canister_id"]
        count = row["count"]
        sender_index = canister_id_to_index[sender_id]
        receiver_index = canister_id_to_index[receiver_id]
        edges[(sender_index, receiver_index)] = count

    load = communicating_canisters[load_type].tolist()

    return {
        "edges": edges,
        "load": load,
        "index_to_canister_id": index_to_canister_id,
    }
