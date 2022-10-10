import base64
import binascii
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from util.print import eprint


# Changes to a subnet
class SubnetParams:
    def __init__(self, subnet_id: str, subnet_type: str):
        self.subnet_id = subnet_id
        self.subnet_type = subnet_type


# Changes to the set of nodes in a subnet
class NodeParams:
    def __init__(self, node_id: str):
        self.node_id = node_id


class NodesubnetParams:
    def __init__(self, node_id: str, subnet_id: str):
        self.node_id = node_id
        self.subnet_id = subnet_id


def quoted(text: str) -> str:
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')


class EsDoc:
    def __init__(self, repr):
        self.repr = repr
        self._parsed_message = None

    def __repr__(self) -> str:
        """Returns internal representation of this EsDoc instance"""
        return self.repr.__repr__()

    def __str__(self) -> str:
        """Returns serialized representation of this EsDoc instance"""
        return self.repr.__str__()

    def id(self) -> str:
        """Returns unique ID of an ES index document"""
        return self.repr["_id"]

    def host(self) -> Dict[str, Any]:
        return self.repr["_source"]["host"]

    @staticmethod
    def _parse_ip_address(addr: str) -> Optional[ipaddress.IPv6Address]:
        if not addr.startswith("ip6"):
            return None
        return ipaddress.IPv6Address(addr[3:].replace("-", ":"))

    def host_addr(self) -> Optional[ipaddress.IPv6Address]:
        host = self.host()
        assert "ip" in host, "host address not found"
        addr_field = host["ip"]
        if isinstance(addr_field, list):
            ext_addrs = []
            for addr in addr_field:
                ip = self._parse_ip_address(addr)
                if ip and not ip.is_link_local:
                    ext_addrs.append(addr)
            if len(ext_addrs) == 0:
                # This may happen early after the host is booted
                return None
            if len(ext_addrs) > 1:
                eprint(f"WARNING: multiple non-link-local addresses specified for host: {', '.join(ext_addrs)}")
            addr = ext_addrs[0]
        else:
            assert isinstance(addr_field, str), f"host.ip has unexpected type: {str(type(addr_field))}"
            addr = addr_field
        return self._parse_ip_address(addr)

    def host_id(self) -> str:
        """Returns a unique identifier that is guaranteed not to change."""
        host = self.host()
        assert "id" in host, f"host.id not found in {str(self)}"
        hid = host["id"]
        assert isinstance(hid, str), f"host.id has unexpected type: {str(type(hid))}"
        assert hid != "", "expected host ID; got empty string"
        return hid

    def message(self) -> str:
        return self.repr["_source"]["message"]

    def component_identifier(self) -> Optional[str]:
        syslog = self.repr["_source"]["syslog"]
        if "identifier" in syslog:
            return syslog["identifier"]
        else:
            return None

    __ES_TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

    def date_time(self) -> datetime:
        """Returns the timestamp of an ES index document"""
        return datetime.strptime(self.repr["_source"]["@timestamp"], EsDoc.__ES_TIMESTAMP_FMT)

    def unix_ts(self) -> int:
        """Returns UNIX standard time in milliseconds"""
        res = self.date_time().timestamp()
        return round(1_000 * res)

    def parse_message(self):
        if self._parsed_message is None:
            self._parsed_message = json.loads(self.message())
        return self._parsed_message

    def is_systemd(self) -> bool:
        return self.component_identifier() == "systemd"

    def is_host_reboot(self) -> bool:
        return self.is_systemd() and self.message() == "Starting IC replica..."

    def is_host_reboot_intent(self) -> bool:
        return self.is_systemd() and self.message() == "Shutting down orchestrator..."

    IDS_OF_COMPONENTS_WITH_STRUCTURED_LOGS = set(
        [
            "orchestrator",
            "ic-btc-adapter",
            "ic-crypto-csp",
            "ic-canister-http-adapter",
            # TODO: all components that use the ReplicaLogger library
        ]
    )

    def is_ic_related(self) -> bool:
        return self.component_identifier() in self.IDS_OF_COMPONENTS_WITH_STRUCTURED_LOGS

    def is_structured(self) -> bool:
        if not self.is_ic_related():
            # Not all orchestrator logs are structured, e.g., NNS canister logs come from orchestrator but are unstructured.
            # However, if logs are not IC-related, they are definitely unstructured.
            return False
        if '"log_entry"' not in self.message():
            # Optimization
            return False
        try:
            msg = self.parse_message()
        except json.decoder.JSONDecodeError:
            # Not all orch documents have structured messages.
            # E.g., NNS canister logs are unstructured.
            return False
        try:
            if "log_entry" not in msg:
                return False
        except TypeError:
            sys.stderr.write(
                f"WARNING: document {str(self)} has message ({str(msg)}) of unexpected type: {type(msg)}\n"
            )
            return False
        return True

    def is_replica(self) -> bool:
        return self.is_structured() and self.component_identifier() == "orchestrator"

    def is_registry_canister(self) -> bool:
        if self.component_identifier() != "orchestrator":
            return False
        if self.is_structured():
            return False

        m = re.match(RegistryDoc.MARKER, self.message())
        if not m:
            return False
        else:
            return True

    class GenericParams:
        """Data class"""

        def __init__(self, component_id: str, level: str, message: str, node_id: str, subnet_id: str):
            self.component_id = component_id
            self.level = level
            self.message = message
            self.node_id = node_id
            self.subnet_id = subnet_id

    def get_generic_params(self) -> Optional[GenericParams]:
        comp = self.component_identifier()
        if self.is_structured():
            r_doc = StructuredDoc(self.repr)
            crate, module = r_doc.get_crate_module()
            component_id = f"{comp}::{crate}::{module}"
            le = r_doc._log_entry()
            lel = le["level"]
            lem = r_doc.get_message()
            node = r_doc.get_node_id()
            subnet = r_doc.get_subnet_id()
            if node == '""':
                return None
        else:
            return None
        return ReplicaDoc.GenericParams(
            component_id=component_id, level=lel, message=quoted(lem), node_id=node, subnet_id=subnet
        )


class RegistryDoc(EsDoc):

    MARKER = r"^\[Canister [\w-]+?\] \[Registry\] (.*)"

    def __init__(self, repr):
        super().__init__(repr)
        assert self.is_registry_canister(), f"Doc {str(self)} is not from the Registry canister"

    def _text(self):
        msg = self.message()
        m = re.match(RegistryDoc.MARKER, msg)
        assert (
            m and len(m.groups()) == 1
        ), f"could not extract text from Registry canister's logs. Unexpected value in field 'message': `{msg}`"
        text = m.group(1)
        return text

    def get_created_subnet(self) -> Optional[SubnetParams]:
        text = self._text()
        m = re.match(r"do_create_subnet: {payload: CreateSubnetPayload {.*}, subnet_id: ([a-z0-9-]*)}", text)
        if not m or len(m.groups()) != 1:
            return None
        subnet_id = m.group(1)
        m1 = re.match(r".*subnet_type: ([A-Za-z]*),.*", text)
        assert m1 is not None and len(m1.groups()) == 1, "invalid CreateSubnetPayload"
        subnet_type = m1.group(1)
        assert (
            subnet_type == "Application" or subnet_type == "System" or subnet_type == "VerifiedApplication"
        ), "invalid subnet_type"
        return SubnetParams(subnet_id, subnet_type)

    def get_updated_subnet(self) -> Optional[SubnetParams]:
        text = self._text()
        m = re.match(r".*subnet_id: ([a-z0-9-]*),.*", text)
        if not m or len(m.groups()) != 1:
            return None
        subnet_id = m.group(1)
        m1 = re.match(r".*subnet_type: Some\(([A-Za-z]*)\),.*", text)
        if not m1 or len(m1.groups()) != 1:
            return None
        subnet_type = m1.group(1)
        assert (
            subnet_type == "Application" or subnet_type == "System" or subnet_type == "VerifiedApplication"
        ), "invalid subnet_type"
        return SubnetParams(subnet_id, subnet_type)

    def get_removed_nodes_from_subnet_params(self) -> Optional[List[NodeParams]]:
        text = self._text()
        m = re.match(
            r"do_remove_nodes_from_subnet finished: RemoveNodesFromSubnetPayload { node_ids: \[(.*?)\] }", text
        )
        if not m or len(m.groups()) != 1:
            m1 = re.match("do_remove_node_directly finished: RemoveNodeDirectlyPayload { node_id: (.*?) }", text)
            if not m1 or len(m1.groups()) != 1:
                return None
            else:
                removed_nodes_str = m1.group(1)
        else:
            removed_nodes_str = m.group(1)
        removed_nodes = removed_nodes_str.split(", ")
        assert len(removed_nodes) > 0, "expected node ids but didn't find any"
        return list(map(lambda node_str: NodeParams(node_str), removed_nodes))

    def get_added_nodes_to_subnet_params(self) -> Optional[List[NodesubnetParams]]:
        text = self._text()
        m = re.match("do_add_nodes_to_subnet finished: AddNodesToSubnetPayload { (.*?) }", text)
        if not m or len(m.groups()) != 1:
            return None
        params = m.group(1)
        m1 = re.match(".*subnet_id: (.*?),.*", params)
        assert (
            m1 and len(m1.groups()) == 1
        ), f"could not parse find `subnet_id` in AddNodesToSubnetPayload with params `{params}`"
        subnet = m1.group(1)
        m2 = re.match(r".*node_ids: \[(.*?)\].*", params)
        assert (
            m2 and len(m2.groups()) == 1
        ), f"could not parse find `node_ids` in AddNodesToSubnetPayload with params `{params}`"
        nodes_str = m2.group(1)
        nodes = nodes_str.split(", ")
        assert len(nodes) > 0, "got empty list of node ids"
        return list(map(lambda n: NodesubnetParams(n, subnet), nodes))

    def get_change_subnet_membership_params(self) -> Optional[Tuple[List[NodesubnetParams], List[NodeParams]]]:
        # TODO: add this function to other places where node add and remove are used elsewhere in the code
        text = self._text()
        m = re.match("do_change_subnet_membership finished: ChangeSubnetMembershipPayload { (.*?) }", text)
        if not m or len(m.groups()) != 1:
            return None
        params = m.group(1)
        m1 = re.match(".*subnet_id: (.*?),.*", params)
        assert (
            m1 and len(m1.groups()) == 1
        ), f"could not parse find `subnet_id` in ChangeSubnetMembershipPayload with params `{params}`"
        subnet = m1.group(1)
        m2 = re.match(r".*node_ids_add: \[(.*?)\].*", params)
        assert (
            m2 and len(m2.groups()) == 1
        ), f"could not parse find `node_ids_add` in ChangeSubnetMembershipPayload with params `{params}`"
        nodes_add_str = m2.group(1)
        nodes_add = nodes_add_str.split(", ")
        assert len(nodes_add) > 0, "got empty list of node ids to add"
        m3 = re.match(r".*node_ids_remove: \[(.*?)\].*", params)
        assert (
            m3 and len(m3.groups()) == 1
        ), f"could not parse find `node_ids_remove` in ChangeSubnetMembershipPayload with params `{params}`"
        nodes_remove_str = m3.group(1)
        nodes_remove = nodes_remove_str.split(", ")
        assert len(nodes_remove) > 0, "got empty list of node ids to remove"
        return list(map(lambda n: NodesubnetParams(n, subnet), nodes_add)), list(
            map(lambda n: NodeParams(n), nodes_remove)
        )

    def get_added_node_to_ic_params(self) -> Optional[NodeParams]:
        text = self._text()
        m = re.match(r"do_add_node finished: AddNodePayload { (.*?) }", text)
        if not m or len(m.groups()) != 1:
            return None
        params = m.group(1)
        m1 = re.match(r".*node_signing_pk: \[(.*?)\],.*", params)
        assert m1 and len(m1.groups()) == 1, "could not extract field node_signing_pk from AddNodePayload"
        pk_str: str = m1.group(1)
        assert isinstance(
            pk_str, str
        ), f"could not extract field node_signing_pk from AddNodePayload (RE group's type is {type(pk_str)})"
        pk = [int(c) for c in pk_str.split(", ")]
        bulb = hashlib.sha224(bytes(pk)).digest()

        def to_be_bytes(n: int) -> bytes:
            return n.to_bytes((n.bit_length() + 7) // 8, "big") or b"\0"

        # Formula according to https://internetcomputer.org/docs/current/references/ic-interface-spec/#textual-ids
        node_id = "-".join(
            (lambda xs: [xs[i : i + 5] for i in range(0, len(xs), 5)])(
                base64.b32encode(to_be_bytes(binascii.crc32(bulb)) + bulb).decode("ascii").rstrip("=").lower()
            )
        )
        return NodeParams(node_id=node_id)

    def get_removed_nodes_from_ic_params(self) -> Optional[List[NodeParams]]:
        text = self._text()
        m = re.match(r"do_remove_nodes finished: RemoveNodesPayload { node_ids: \[(.*?)\] }", text)
        if not m or len(m.groups()) != 1:
            return None
        removed_nodes_str = m.group(1)
        removed_nodes = removed_nodes_str.split(", ")
        assert len(removed_nodes) > 0, "expected node ids but didn't find any"
        return list(map(lambda node_str: NodeParams(node_str), removed_nodes))


class StructuredDoc(EsDoc):
    def __init__(self, repr):
        super().__init__(repr)
        assert self.is_structured(), f"Doc {str(self)} is unstructured"

    def _log_entry(self):
        return self.parse_message()["log_entry"]

    def get_message(self):
        le = self._log_entry()
        return le["message"].replace("\n", "<br>")

    def get_crate_module(self) -> Tuple[str, str]:
        le = self._log_entry()
        return le["crate_"], le["module"]

    def get_node_id(self) -> str:
        """Returns the principal of the node that produced this log."""
        le = self._log_entry()
        return quoted(le["node_id"])

    def get_subnet_id(self) -> str:
        """Returns the principal of the subnet to which this node belongs to."""
        le = self._log_entry()
        return quoted(le["subnet_id"])


class ReplicaDoc(StructuredDoc):
    def __init__(self, repr):
        super().__init__(repr)
        assert self.component_identifier() == "orchestrator", f"Doc {str(self)} is not from the replica"

    def get_subnet_type(self) -> Optional[Tuple[str, str]]:
        m = re.search(
            r"{subnet_record: Registry subnet record SubnetRecord {.*subnet_type: ([A-Za-z]*),.*}, subnet_id: ([a-z0-9-]*)}",
            self.get_message(),
        )
        if m:
            assert len(m.groups()) == 2
            subnet_type = m.group(1)
            assert (
                subnet_type == "Application" or subnet_type == "System" or subnet_type == "VerifiedApplication"
            ), "invalid subnet_type"
            subnet_id = m.group(2)
            return (subnet_id, subnet_type)
        return None

    # Consensus finalization
    class ConsensusFinalizationParams:
        """Data class"""

        def __init__(self, is_state_available: bool, is_key_available: bool):
            self.is_state_available = is_state_available
            self.is_key_available = is_key_available

    # https://gitlab.com/dfinity-lab/public/ic/-/blob/64f34f254c9c98ee9f717941d6c9679051ba804e/rs/consensus/src/consensus.rs#L433
    def get_consensus_finalized_params(self) -> Optional[ConsensusFinalizationParams]:

        lem = self.get_message()
        if "Consensus finalized height" not in lem:
            return None
        else:
            m = re.match(".*state available: (false|true).*DKG key material available: (false|true).*", lem)
            if not m or len(m.groups()) < 2:
                eprint(
                    f"WARNING: could not parse "
                    f"consensus_finalized_params in "
                    f"orchestrator document {self.id()}: {lem}"
                )
                return None
            else:
                return ReplicaDoc.ConsensusFinalizationParams(
                    is_state_available=(m.group(1) == "true"), is_key_available=(m.group(2) == "true")
                )

    def get_p2p_node_params(self, verb: str) -> Optional[NodeParams]:
        m = re.match("Nodes (.*?) %s" % verb, self.get_message())
        if not m or len(m.groups()) < 1:
            return None
        else:
            node_id_str = m.group(1)
            if " " in node_id_str:
                eprint(
                    f"WARNING: multiple nodes not yet supported "
                    f"in get_p2p_node_params; see doc {self.id()}: "
                    f"{node_id_str}"
                )
                return None
            return NodeParams(node_id=node_id_str)

    def get_p2p_node_added_params(self) -> Optional[NodeParams]:
        return self.get_p2p_node_params(verb="added")

    def get_p2p_node_removed_params(self) -> Optional[NodeParams]:
        return self.get_p2p_node_params(verb="removed")

    class StateManagerReplicaDivergedParams:
        """Data class"""

        def __init__(self, height: int):
            self.height = height

    # {"log_entry":{"level":"CRITICAL","utc_time":"2021-11-25T11:40:22.215Z","message":"Replica diverged at height 10","crate_":"ic_state_manager","module":"ic_state_manager","line":2357,"node_id":"ux3rh-eqec7-sp4an-cvxzj-4mzgl-a4qba-ukccb-r5upa-njbya-rrsj4-yqe","subnet_id":"cpv7s-uecxn-abdz5-xkr3l-l5exk-f54in-66ebe-kyquf-ov2zm-wcq2m-nqe"}}
    def state_manager_replica_diverged_params(self) -> Optional[StateManagerReplicaDivergedParams]:

        m = re.match(r"Replica diverged at height (\d+)", self.get_message())
        if not m or len(m.groups()) < 1:
            return None
        else:
            return ReplicaDoc.StateManagerReplicaDivergedParams(height=int(m.group(1)))

    class CatchUpPackageShare:
        """Data class"""

        def __init__(self, height: int):
            self.height = height

    # https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/consensus/src/consensus/catchup_package_maker.rs?L216&subtree=true
    def get_catchup_package_share_params(self) -> Optional[CatchUpPackageShare]:
        lem = self.get_message()
        m = re.match(r"Proposing a CatchUpPackageShare at height (\d+)", lem)
        if not m or len(m.groups()) < 1:
            return None
        else:
            return ReplicaDoc.CatchUpPackageShare(height=int(m.group(1)))

    class ControlPlaneTlsServerHandshakeFailureParams:
        """Data class"""

        def __init__(self, node_addr: str, peer_addr: str):
            self.node_addr = node_addr
            self.peer_addr = peer_addr

    # Warn "ControlPlane::spawn_accept_task(): tls_server_handshake failed: error = UnauthenticatedClient, local_addr = {:?}, peer_addr = {:?}"
    def get_control_plane_spawn_accept_task_tls_server_handshake_failed_params(
        self,
    ) -> Optional[ControlPlaneTlsServerHandshakeFailureParams]:

        m = re.match(
            r"ControlPlane::spawn_accept_task\(\): tls_server_handshake failed: "
            r"error = (.*?), local_addr = (.*?), peer_addr = (.*?)",
            self.get_message(),
        )
        if not m or len(m.groups()) != 5:
            return None

        # E.g., "UnauthenticatedClient" or
        # "HandshakeError { internal_error: \"(.*?)\" }"
        error_str = m.group(1)
        if error_str != "UnauthenticatedClient":
            return None

        return ReplicaDoc.ControlPlaneTlsServerHandshakeFailureParams(
            node_addr=m.group(2),
            peer_addr=m.group(3),
        )

    class ProposalParams:
        """Data class"""

        def __init__(self, block_hash: str, signer: str, rank: Optional[int] = None):
            self.block_hash = block_hash
            self.signer = signer
            self.rank = rank

    @staticmethod
    def extract_proposal_params(log_entry_msg: str) -> Optional[ProposalParams]:
        m1 = re.match(r".*CryptoHash\(0x(.*?)\).*", log_entry_msg)
        if not m1 or len(m1.groups()) != 1:
            return None

        m2 = re.match(r".*signer: (.*?)\s*\}.*", log_entry_msg)
        if not m2 or len(m2.groups()) != 1:
            return None
        else:
            return ReplicaDoc.ProposalParams(block_hash=m1.group(1), signer=m2.group(1))

    # Jan 20 09:03:22 medium05-1-2 orchestrator[817]: {"log_entry":{"level":"INFO","utc_time":"2022-01-20T09:03:22.721Z","message":"Moved proposal Signed { content: CryptoHash(0xa9643feda6a22d10b9e8453a72aaa7dd737ca35568aa197511173397979b4466), signature: BasicSignature { signature: BasicSig([166, 34, 28, 142, 115, 226, 234, 106, 174, 192, 206, 125, 78, 170, 234, 140, 61, 152, 1, 112, 100, 14, 231, 113, 209, 128, 109, 228, 154, 110, 105, 11, 62, 21, 198, 47, 2, 175, 193, 3, 241, 14, 10, 132, 48, 53, 56, 89, 233, 99, 217, 11, 255, 246, 135, 78, 80, 176, 176, 162, 16, 205, 250, 10]), signer: gvtfg-7gy73-jjgfh-6g6lv-sywtx-vk6xk-qfmrk-cabe4-uggxn-t7joz-zqe } } of rank Rank(0) to artifact pool","crate_":"ic_artifact_manager","module":"processors","line":381,"node_id":"zxdg4-ha7p6-dfvi3-eo5rs-rcvbi-pkuwu-scoy3-5lk6t-2bcvs-c3txn-xqe","subnet_id":"62e3r-apw4o-mhxv3-xidd3-ngrxx-mnunc-xhlku-wkybu-yhq5o-mg2ou-3ae"}}
    def get_proposal_moved_params(self) -> Optional[ProposalParams]:
        lem: str = self.get_message()
        marker = "Moved proposal Signed"
        if not lem.startswith(marker):
            return None
        return ReplicaDoc.extract_proposal_params(lem)

    # debug!(
    #     self.log,
    #     "Added proposal {:?} of rank {:?} to artifact pool", p, rank
    # ); // https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/artifact_manager/src/processors.rs?L357
    # debug!(
    #     self.log,
    #     "Moved proposal {:?} of rank {:?} to artifact pool", p, rank
    # ); // https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/artifact_manager/src/processors.rs?L370
    def get_validated_block_proposal_params(self, verb: str) -> Optional[ProposalParams]:

        lem: str = self.get_message()
        marker = rf"^{verb} proposal (.*?) of rank Rank\((.*?)\) to artifact pool$"
        m = re.match(marker, lem)
        if not m or len(m.groups()) != 2:
            return None
        proposal = m.group(1)
        res = ReplicaDoc.extract_proposal_params(proposal)
        assert res is not None, f"cannot extract proposal params from `{proposal}`"
        res.rank = int(m.group(2))
        return res

    class BatchDeliveryParams:
        """Data class"""

        def __init__(self, block_hash: str):
            self.block_hash = block_hash

    # https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/consensus/src/consensus/batch_delivery.rs?L157&subtree=true
    def get_batch_delivery_params(self) -> Optional[BatchDeliveryParams]:
        m = re.match('.*block_hash \\"(.*?)\\".*', self.get_message())
        if not m or len(m.groups()) < 1:
            return None
        else:
            return ReplicaDoc.BatchDeliveryParams(block_hash=m.group(1))

    class ConsensusParams:
        """Data class"""

        def __init__(self, height: str, hash: str, replica_version: str):
            self.height = height
            self.hash = hash
            self.replica_version = replica_version

    # https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/consensus/src/consensus/batch_delivery.rs?L69
    def get_batch_delivery_consensus_params(self) -> Optional[ConsensusParams]:
        le = self._log_entry()
        if "consensus" in le:
            con = le["consensus"]
            return ReplicaDoc.ConsensusParams(
                height=con["height"], hash=con["hash"], replica_version=con["replica_version"]
            )
        else:
            return None
