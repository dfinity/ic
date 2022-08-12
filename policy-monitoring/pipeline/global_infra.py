import json
from ipaddress import IPv6Address
from ipaddress import IPv6Network
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

from util.yaml import yaml

from .es_doc import ReplicaDoc


class GlobalInfra:
    class Error(Exception):
        """An exception while inferring GlobalInfra"""

        pass

    known_hosts: Set[IPv6Address]
    host_addr_to_node_id_map: Dict[IPv6Address, str]
    node_id_to_host_map: Dict[str, IPv6Address]
    original_subnet_types: Dict[str, str]
    in_subnet_relations: Dict[str, List[Tuple[int, str]]]
    original_subnet_membership: Dict[str, str]

    def __init__(self, source: str):
        # original source of this Global Infra information
        self.source = source
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

    @staticmethod
    def get_host_dc(host_ip: IPv6Address) -> IPv6Network:
        """Maps host_ip to data center mask"""
        return IPv6Network(f"{host_ip}/64", strict=False)

    def is_known_host(self, host_addr: IPv6Address) -> bool:
        return host_addr in self.known_hosts

    def get_host_ip_addr(self, node_id: str) -> IPv6Address:
        """Returns host_ipv6 based on node_id"""
        return self.node_id_to_host_map[node_id]

    def get_original_subnet_types(self) -> Dict[str, str]:
        return self.original_subnet_types

    def get_original_subnet_membership(self) -> Dict[str, str]:
        return self.original_subnet_membership

    def get_original_nodes(self) -> Dict[IPv6Address, str]:
        return self.host_addr_to_node_id_map

    @classmethod
    def _get_dc_info_impl(Self, node_addrs: Set[IPv6Address]) -> Dict[IPv6Network, Set[IPv6Address]]:
        dcs: Dict[IPv6Network, Set[IPv6Address]] = dict()
        for addr in node_addrs:
            dc = Self.get_host_dc(addr)
            if dc in dcs:
                dcs[dc].add(addr)
            else:
                dcs[dc] = set([addr])
        return dcs

    def _get_dc_info(self) -> Dict[IPv6Network, Set[IPv6Address]]:
        """Returns a map from data center ipv6 to set of host ipv6s"""
        return self._get_dc_info_impl(self.known_hosts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "subnets": self.in_subnet_relations,
            "original_subnet_types": self.get_original_subnet_types(),
            "original_subnet_membership": self.get_original_subnet_membership(),
            "data_centers": self._get_dc_info(),
            "host_addr_to_node_id_mapping": self.host_addr_to_node_id_map,
        }

    @classmethod
    def fromDict(Self, d: Dict[str, Any], source: str) -> "GlobalInfra":
        infra = GlobalInfra(source)
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
        return GlobalInfra.fromDict(d, source=str(input_file))

    @classmethod
    def _fromIcRegeditSnapshot(Self, j: Any) -> "GlobalInfra":
        d: Dict[str, Any] = dict()

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
        d["data_centers"] = Self._get_dc_info_impl(set(host_ips.keys()))

        return GlobalInfra.fromDict(d, "<obtained_from_registry_snapshot>")

    @classmethod
    def fromIcRegeditSnapshotBulb(Self, input_bulb: str) -> "GlobalInfra":
        j = json.loads(input_bulb)
        return Self._fromIcRegeditSnapshot(j)

    @classmethod
    def fromIcRegeditSnapshotFile(Self, input_file: Path) -> "GlobalInfra":

        with open(input_file, "r") as fin:
            j = json.load(fin)

        return Self._fromIcRegeditSnapshot(j)

    @classmethod
    def fromReplicaLogs(Self, replica_docs: List[ReplicaDoc]) -> "GlobalInfra":
        infra = GlobalInfra(source="<inferred_from_replica_logs>")
        for doc in replica_docs:
            # Process all replica docs' node_id / subnet data
            unix_ts, node_id, subnet_id, subnet_type = (
                doc.unix_ts(),
                doc.get_node_id(),
                doc.get_subnet_id(),
                doc.get_subnet_type(),
            )

            if subnet_type is not None:
                (sub_id, sub_type) = subnet_type
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

        infra.node_id_to_host_map = {
            node_id: host_addr for host_addr, node_id in infra.host_addr_to_node_id_map.items()
        }
        return infra
