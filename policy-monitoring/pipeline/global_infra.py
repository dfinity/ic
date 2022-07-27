import json
from ipaddress import IPv6Address
from ipaddress import IPv6Network
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from util.yaml import yaml

from .es_doc import ReplicaDoc


def rotate(info: Dict[str, List[Tuple[int, str]]], sorted=True) -> Dict[str, List[Tuple[int, str]]]:
    """
    Take a dict [info] that maps, e.g., x, y, z to:
       [(t1, A), (t2, B)],
       [(t3, C), (t4, D)],
       [(t3, B), (t4, D)], resp.
    Return a new dict mapping A, B, C, D to:
       [(t1, x)],
       [(t3, x), (t4, z)],
       [(t3, y)].
       [(t3, y), (t4, z)].
    If [sorted], then all list elements will be (ascendingly) sorted by ts.
    """
    res: Dict[str, List[Tuple[int, str]]] = dict()
    for key, memberships in info.items():
        for unix_ts, value in memberships:
            if value in res:
                res[value].append((unix_ts, key))
            else:
                res[value] = [(unix_ts, key)]
    if sorted:
        # Sort all members by the timestamps
        for members in res.values():
            members.sort(key=lambda m: m[0])
    return res


class GlobalInfra:
    class Error(Exception):
        """An exception while inferring GlobalInfra"""

        pass

    prefixes: Optional[List[IPv6Network]]
    known_hosts: Set[IPv6Address]
    host_addr_to_node_id_map: Dict[IPv6Address, str]
    node_id_to_host_map: Dict[str, IPv6Address]
    original_subnet_types: Dict[str, str]
    in_subnet_relations: Dict[str, List[Tuple[int, str]]]
    original_subnet_membership: Dict[str, str]

    def __init__(self):
        self.prefixes = None
        # stores host_ipv6s
        self.known_hosts = set()
        # maps host_ipv6 to node_id
        self.host_addr_to_node_id_map = dict()
        # maps subnet_id to its initial subnet_type
        self.original_subnet_types = dict()
        # maps subnet_id to (sorted) list of (unix_ts, node_ids)
        self.in_subnet_relations = dict()
        # maps node_id to the very first subnet it reports being assigned to
        self.original_subnet_membership = dict()

    def get_host_dc(self, host_ip_str: IPv6Address) -> IPv6Network:
        """Maps host_ip to data center mask"""
        assert self.prefixes is not None, "cannot call GlobalInfra.host_dc() as self.prefixes is None"
        host_ip = IPv6Address(host_ip_str)
        for prefix in self.prefixes:
            if host_ip in prefix:
                return prefix
        raise KeyError("Could not identify data center for host %d" % host_ip)

    def is_known_host(self, host_addr: IPv6Address) -> bool:
        return host_addr in self.known_hosts

    def get_host_ip_addr(self, node_id: str) -> IPv6Address:
        """Returns host_ipv6 based on node_id"""
        return self.node_id_to_host_map[node_id]

    def get_original_subnet_types(self) -> Dict[str, str]:
        return self.original_subnet_types

    def get_original_subnet_membership(self) -> Dict[str, str]:
        return self.original_subnet_membership

    def _get_dc_info(self) -> Optional[Dict[IPv6Network, Set[IPv6Address]]]:
        """Returns a map from data center ipv6 to set of host ipv6s"""
        if self.prefixes is None:
            return None
        dcs: Dict[IPv6Network, Set[IPv6Address]]
        dcs = dict()
        for host_addr in self.known_hosts:
            host_ipv6 = IPv6Address(host_addr)
            for prefix in self.prefixes:
                if host_ipv6 in prefix:
                    if prefix in dcs:
                        dcs[prefix].add(host_ipv6)
                    else:
                        dcs[prefix] = set([host_ipv6])
        return dcs

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subnets": self.in_subnet_relations,
            "original_subnet_types": self.get_original_subnet_types(),
            "original_subnet_membership": self.get_original_subnet_membership(),
            "data_centers": self._get_dc_info(),
            "host_addr_to_node_id_mapping": self.host_addr_to_node_id_map,
        }

    @classmethod
    def fromDict(Self, d: Dict[str, Any]) -> "GlobalInfra":
        infra = GlobalInfra()
        infra.prefixes = list(d["data_centers"].keys())
        infra.original_subnet_types = d["original_subnet_types"]
        infra.original_subnet_membership = d["original_subnet_membership"]
        infra.host_addr_to_node_id_map = d["host_addr_to_node_id_mapping"]
        infra.known_hosts = set([node_ip for node_ips in d["data_centers"].values() for node_ip in node_ips])
        infra.node_id_to_host_map = {
            node_id: host_addr for host_addr, node_id in infra.host_addr_to_node_id_map.items()
        }
        infra.in_subnet_relations = d["subnets"]
        return infra

    @classmethod
    def fromYamlFile(Self, input_file: Path) -> "GlobalInfra":
        d: Dict[str, Any] = dict()
        with open(input_file, "r") as fin:
            d = yaml.full_load(stream=fin)
        return GlobalInfra.fromDict(d)

    @classmethod
    def fromIcRegeditSnapshot(Self, input_file: Path) -> "GlobalInfra":
        d: Dict[str, Any] = dict()
        with open(input_file, "r") as fin:
            j = json.load(fin)

        def int_to_subnet_type(x: str, subnet_id: str) -> str:
            if x == 4:
                return "Application"
            if x == 1:
                return "SecureApplication"
            if x == 2:
                return "System"
            raise GlobalInfra.Error(f"unsupported subnet type {x} for {subnet_id}")

        subnets = list(map(lambda x: x[len("(principal-id)") :], j["subnet_list"]["subnets"]))
        nodes = list(map(lambda x: x[len("node_record_") :], filter(lambda k: k.startswith("node_record_"), j.keys())))
        d["original_subnet_types"] = {
            subnet_id: int_to_subnet_type(j[f"subnet_record_{subnet_id}"]["subnet_type"], subnet_id)
            for subnet_id in subnets
        }

        memberships: Dict[str, str] = dict()  # maps node ids to subnet ids
        for subnet_id in subnets:
            for member in map(lambda x: x[len("(principal-id)") :], j[f"subnet_record_{subnet_id}"]["membership"]):
                if member in memberships:
                    raise GlobalInfra.Error(
                        f"Node {member} is a member of more than one subnet, e.g.: "
                        f"{memberships[member]} and {subnet_id}"
                    )
                else:
                    memberships[member] = subnet_id
        d["original_subnet_membership"] = memberships
        reg_timestamp = 0  # information about subnets is relevant to all consecutive time points
        d["subnets"] = {
            subnet_id: [
                (reg_timestamp, node_id)
                for node_id in map(lambda x: x[len("(principal-id)") :], j[f"subnet_record_{subnet_id}"]["membership"])
            ]
            for subnet_id in subnets
        }

        host_ips = {IPv6Address(j[f"node_record_{node_id}"]["http"]["ip_addr"]): node_id for node_id in nodes}
        d["host_addr_to_node_id_mapping"] = host_ips

        dcs: Dict[IPv6Network, Set[IPv6Address]] = dict()
        for node_addr in host_ips.keys():
            node_addr = IPv6Address(node_addr)
            dc = IPv6Network(f"{node_addr}/64", strict=False)
            if dc in dcs:
                dcs[dc].add(node_addr)
            else:
                dcs[dc] = set([node_addr])

        d["data_centers"] = dcs

        return GlobalInfra.fromDict(d)

    @classmethod
    def fromReplicaLogs(Self, replica_docs: List[ReplicaDoc]) -> "GlobalInfra":
        infra = GlobalInfra()
        for doc in replica_docs:
            # Process all replica docs' node_id / subnet data
            unix_ts, node_id, subnet_id, subnet_id_type = (
                doc.unix_ts(),
                doc.get_host_principal(),
                doc.get_subnet_principal(),
                doc.get_subnet_type(),
            )

            if subnet_id_type is not None:
                (sub_id, sub_type) = subnet_id_type
                if sub_id not in infra.original_subnet_types:
                    infra.original_subnet_types[sub_id] = sub_type

            if not subnet_id:
                # assert not node_id
                pass
            elif node_id:
                # Compute in_subnet_relations
                if node_id in infra.in_subnet_relations:
                    subnet_memberships = infra.in_subnet_relations[node_id]
                    _, last_subnet = subnet_memberships[-1]
                    if subnet_id != last_subnet:
                        subnet_memberships.append((unix_ts, subnet_id))
                else:
                    infra.original_subnet_membership[node_id] = subnet_id
                    infra.in_subnet_relations[node_id] = [(unix_ts, subnet_id)]

            # Find a replica doc defining data center prefixes
            if not infra.prefixes:
                infra.prefixes = doc._get_ipv6_prefixes()

            host_addr = doc.host_addr()
            infra.known_hosts.add(host_addr)

            # Compute host_addr_to_node_id_map
            if host_addr in infra.host_addr_to_node_id_map:
                old_node_id = infra.host_addr_to_node_id_map[host_addr]
                assert (
                    old_node_id == node_id
                ), f"Host {str(host_addr)} is mapped to more than one node ID, e.g., {old_node_id} and {node_id}"
            else:
                infra.host_addr_to_node_id_map[host_addr] = node_id

        if not infra.prefixes:
            raise GlobalInfra.Error(
                "Cannot find data center prefixes in ORCH logs. Consider downloading more ES logs.\n"
            )

        infra.node_id_to_host_map = {
            node_id: host_addr for host_addr, node_id in infra.host_addr_to_node_id_map.items()
        }
        return infra
