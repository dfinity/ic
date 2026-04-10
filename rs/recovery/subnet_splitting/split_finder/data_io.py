from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd


def load_subnet_data(load_path: Path, load_type: str, comm_data_path: Path) -> Dict:
    """
    Load canister metadata and communication edges for a subnet.
    Returns canister DataFrame, edge list (i, j, weight), load vector, and index mappings.
    """
    canister_data = pd.read_csv(load_path)
    canister_data = canister_data[["canister_id", load_type]]
    canister_data["original_index"] = range(len(canister_data))

    comm_data = pd.read_csv(comm_data_path)
    comm_data = comm_data[["sender_canister_id", "receiver_canister_id", "count"]]

    communicating_canister_ids = set(comm_data["sender_canister_id"]).union(set(comm_data["receiver_canister_id"]))
    communicating_canisters = canister_data[canister_data["canister_id"].isin(communicating_canister_ids)].reset_index(
        drop=True
    )

    incoming_messages = comm_data.groupby("receiver_canister_id")["count"].sum().reset_index()
    incoming_messages.columns = ["canister_id", "total_incoming"]
    communicating_canisters["total_incoming"] = communicating_canisters.merge(
        incoming_messages, on="canister_id", how="left"
    )["total_incoming"].fillna(0)

    communicating_canisters["index"] = range(len(communicating_canisters))
    N_c = len(communicating_canisters)

    canister_id_to_index = dict(zip(communicating_canisters["canister_id"], communicating_canisters["index"]))
    index_to_canister_id = dict(zip(communicating_canisters["index"], communicating_canisters["canister_id"]))

    edges: List[Tuple[int, int, float]] = []
    for _, row in comm_data.iterrows():
        sender_id = row["sender_canister_id"]
        receiver_id = row["receiver_canister_id"]
        count = row["count"]
        if sender_id in canister_id_to_index and receiver_id in canister_id_to_index:
            i = canister_id_to_index[sender_id]
            j = canister_id_to_index[receiver_id]
            edges.append((i, j, count))

    load_incoming = communicating_canisters["total_incoming"].tolist()
    load = communicating_canisters[load_type].tolist()

    return {
        "communicating_canisters": communicating_canisters,
        "edges": edges,
        "load_incoming": load_incoming,
        "load": load,
        "index_to_canister_id": index_to_canister_id,
        "comm_data": comm_data,
        "N_c": N_c,
    }
