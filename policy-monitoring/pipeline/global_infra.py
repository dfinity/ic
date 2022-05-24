import ipaddress
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from .es_doc import ReplicaDoc


class GlobalInfra:
    class Error(Exception):
        """An exception while inferring GlobalInfra"""

        pass

    prefixes: Optional[List[ipaddress.IPv6Network]]
    known_hosts: Set[str]
    host_addr_to_node_id_map: Dict[str, str]
    node_id_to_host_map: Dict[str, str]
    original_subnet_types: Dict[str, str]
    in_subnet_relations: Dict[str, List[Tuple[int, str]]]
    original_subnet_membership: Dict[str, str]

    def __init__(self, replica_docs: List[ReplicaDoc]):
        self.prefixes = None
        # stores host_ipv6s
        self.known_hosts = set()
        # maps host_ipv6 to node_id
        self.host_addr_to_node_id_map = dict()
        # maps subnet_id to its initial subnet_type
        self.original_subnet_types = dict()
        # maps node_id to (sorted) list of (unix_ts, node_ids)
        self.in_subnet_relations = dict()
        # maps node_id to the very first subnet it reports being assigned to
        self.original_subnet_membership = dict()

        for doc in replica_docs:
            # Process all replica docs' node_id / subnet data
            unix_ts, node_id, subnet_id, subnet_id_type = (
                doc.unix_ts(),
                doc.get_node_id(),
                doc.get_subnet_id(),
                doc.get_subnet_type(),
            )

            if subnet_id_type is not None:
                (sub_id, sub_type) = subnet_id_type
                if sub_id not in self.original_subnet_types:
                    self.original_subnet_types[sub_id] = sub_type

            if not subnet_id:
                # assert not node_id
                pass
            elif node_id:
                # Compute in_subnet_relations
                if node_id in self.in_subnet_relations:
                    subnet_memberships = self.in_subnet_relations[node_id]
                    _, last_subnet = subnet_memberships[-1]
                    if subnet_id != last_subnet:
                        subnet_memberships.append((unix_ts, subnet_id))
                else:
                    self.original_subnet_membership[node_id] = subnet_id
                    self.in_subnet_relations[node_id] = [(unix_ts, subnet_id)]

            # Find a replica doc defining data center prefixes
            if not self.prefixes:
                self.prefixes = doc.get_ipv6_prefixes()

            host_addr = doc.host_addr()
            self.known_hosts.add(host_addr)

            # Compute host_addr_to_node_id_map
            if node_id:
                if host_addr in self.host_addr_to_node_id_map:
                    old_node_id = self.host_addr_to_node_id_map[host_addr]
                    assert old_node_id == node_id, (
                        f"Host {str(host_addr)} is mapped to more than one"
                        f" node ID, e.g., {old_node_id} and {node_id}"
                    )
                else:
                    self.host_addr_to_node_id_map[host_addr] = node_id

        if not self.prefixes:
            raise GlobalInfra.Error(
                "Cannot find data center prefixes in ORCH logs. Consider downloading more ES logs.\n"
            )

        self.node_id_to_host_map = {node_id: host_addr for host_addr, node_id in self.host_addr_to_node_id_map.items()}

    def get_host_dc(self, host_ip_str: str) -> ipaddress.IPv6Network:
        """Maps host_ip to data center mask"""
        assert self.prefixes is not None, "cannot call GlobalInfra.host_dc() as self.prefixes is None"
        host_ip = ipaddress.IPv6Address(host_ip_str)
        for prefix in self.prefixes:
            if host_ip in prefix:
                return prefix
        raise KeyError("Could not identify data center for host %d" % host_ip)

    def is_known_host(self, host_addr: str) -> bool:
        return host_addr in self.known_hosts

    def get_host_ip_addr(self, node_id: str) -> str:
        """Returns host_ipv6 based on node_id"""
        return self.node_id_to_host_map[node_id]

    def get_subnet_info(self) -> Dict[str, List[Tuple[int, str]]]:
        res: Dict[str, List[Tuple[int, str]]] = dict()
        for node_id, memberships in self.in_subnet_relations.items():
            for unix_ts, subnet_id in memberships:
                if subnet_id in res:
                    res[subnet_id].append((unix_ts, node_id))
                else:
                    res[subnet_id] = [(unix_ts, node_id)]
        # Sort all members by the timestamps
        for members in res.values():
            members.sort(key=lambda m: m[0])
        return res

    def get_original_subnet_types(self) -> Dict[str, str]:
        return self.original_subnet_types

    def get_original_subnet_membership(self) -> Dict[str, str]:
        return self.original_subnet_membership

    def get_dc_info(self) -> Dict[ipaddress.IPv6Network, Set[ipaddress.IPv6Address]]:
        """Returns a map from data center ipv6 to set of host ipv6s"""
        assert self.prefixes is not None, "cannot call GlobalInfra.get_dc_info() as self.prefixes is None"
        dcs: Dict[ipaddress.IPv6Network, Set[ipaddress.IPv6Address]]
        dcs = dict()
        for host_addr in self.known_hosts:
            host_ipv6 = ipaddress.IPv6Address(host_addr)
            for prefix in self.prefixes:
                if host_ipv6 in prefix:
                    if prefix in dcs:
                        dcs[prefix].add(host_ipv6)
                    else:
                        dcs[prefix] = set([host_ipv6])
        return dcs

    def get_host_addr_to_node_id_mapping(self) -> Dict[str, str]:
        return self.host_addr_to_node_id_map
