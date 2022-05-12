import ipaddress
import json
import re
import sys
from datetime import datetime
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple


# Changes to the set of nodes in a subnet
class NodeParams:
    def __init__(self, node_id: str):
        self.node_id = node_id


class NodesubnetParams:
    def __init__(self, node_id: str, subnet_id: str):
        self.node_id = node_id
        self.subnet_id = subnet_id


def quoted(text: str) -> str:
    return '"%s"' % text.replace('"', '\\"')


class EsDoc:
    def __init__(self, repr):
        self.repr = repr
        self.parsed_message = None

    def __repr__(self) -> str:
        """Returns internal representation of this EsDoc instance"""
        return self.repr.__repr__()

    def __str__(self) -> str:
        """Returns serialized representation of this EsDoc instance"""
        return self.repr.__str__()

    def id(self) -> str:
        """Returns unique ID of an ES index document"""
        return self.repr["_id"]

    def host(self) -> Dict[str, str]:
        return self.repr["_source"]["host"]

    def host_addr(self) -> str:
        hostname = self.host()["hostname"]
        if hostname in ["localhost", "blank"]:
            return hostname
        else:
            # E.g. ip62001-4d78-40d-0-5000-51ff-fe05-3b52
            assert hostname.startswith("ip6"), f"expected IPv6 but found `{hostname}`"
            addr_str = hostname[3:].replace("-", ":")
            return addr_str

    def message(self) -> str:
        return self.repr["_source"]["message"]

    def component_identifier(self) -> str:
        return self.repr["_source"]["syslog"]["identifier"]

    __ES_TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

    def date_time(self) -> datetime:
        """Returns the timestamp of an ES index document"""
        return datetime.strptime(self.repr["_source"]["@timestamp"], EsDoc.__ES_TIMESTAMP_FMT)

    def unix_ts(self) -> int:
        """Returns UNIX standard time in milliseconds"""
        res = self.date_time().timestamp()
        return round(1_000 * res)

    def parse_message(self):
        if self.parsed_message is None:
            self.parsed_message = json.loads(self.message())
        return self.parsed_message

    def is_systemd(self) -> bool:
        return self.component_identifier() == "systemd"

    def is_host_reboot(self) -> bool:
        return self.is_systemd() and self.message() == "Starting IC replica..."

    def is_replica(self) -> bool:
        if self.component_identifier() != "orchestrator":
            return False
        try:
            msg = self.parse_message()
        except json.decoder.JSONDecodeError:
            # Not all orch documents have structured messages.
            # E.g., NNS canister logs are unstructured.
            return False
        try:
            if "log_entry" not in msg:
                # FIXME uncomment
                # sys.stderr.write("WARNING: orchestrator document {doc} with message" + \
                #                  " ({msg}) has no 'log_entry'\n".format(
                #                     doc=self.id(),
                #                     msg=self.message()))
                return False
        except TypeError:
            sys.stderr.write(
                f"WARNING: orchestrator document {str(self)} has "
                f"message ({str(msg)}) of unexpected type: {type(msg)}\n"
            )
            return False
        return True

    def is_registry_canister(self) -> bool:
        if self.component_identifier() != "orchestrator":
            return False
        if self.is_replica():
            return False

        m = re.match(RegistryDoc.MARKER, self.message())
        if not m:
            return False
        else:
            return True


class RegistryDoc(EsDoc):

    MARKER = r"^\[Canister [\w-]+?\] \[Registry Canister\] (.*)"

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

    #   {'_index': 'journalbeat-guestos-journal-7.5.1-2022.04.06', '_type': '_doc', '_id': 'IieN_n8BwsYIEpayu7hb', '_score': None, '_source': {'@timestamp': '2022-04-06T11:06:12.877Z', 'ecs': {'version': '1.1.0'}, 'event': {'created': '2022-04-06T11:06:13.510Z'}, 'systemd': {'unit': 'ic-replica.service', 'invocation_id': '4fbe6c1c49c445a78a4b1381b1959952', 'cgroup': '/system.slice/ic-replica.service', 'transport': 'stdout', 'slice': 'system.slice'}, 'syslog': {'facility': 3, 'identifier': 'orchestrator', 'priority': 6}, 'host': {'hostname': 'ip62001-4d78-40d-0-5000-cff-fe43-51cd', 'boot_id': '3a2713e18abf4212acce647f349ebace', 'id': '9b0d3813efd443ca9adaaeae0c4351cd', 'name': 'ip62001-4d78-40d-0-5000-cff-fe43-51cd'}, 'tags': ['system_test', 'hourly__node_reassignment_pot-2298485185'], 'agent': {'ephemeral_id': 'c32b94ad-c1c1-4742-82a7-d0a390b158bc', 'hostname': 'ip62001-4d78-40d-0-5000-cff-fe43-51cd', 'id': '716933ec-f7b2-4c18-b8e7-c33954759f9e', 'version': '7.5.1', 'type': 'journalbeat'}, 'process': {'capabilites': '0', 'cmd': '/opt/ic/bin/canister_sandbox --embedder-config {"max_wasm_stack_size":5242880,"query_execution_threads":2,"max_globals":200,"max_functions":6000,"max_custom_sections":16,"max_custom_sections_size":1048576,"feature_flags":{"api_cycles_u128_flag":"Enabled","rate_limiting_of_debug_prints":"Enabled"}} rwlgt-iiaaa-aaaaa-aaaaa-cai', 'name': 'canister_sandbo', 'executable': '/opt/ic/bin/canister_sandbox', 'pid': 1009, 'uid': 108}, 'message': '[Canister rwlgt-iiaaa-aaaaa-aaaaa-cai] [Registry Canister] do_remove_nodes_from_subnet finished: RemoveNodesFromSubnetPayload { node_ids: [uoels-4c3q4-lhton-kfjlf-e2j5w-gsg3m-7pan7-6ubmq-mgqva-4i3op-pae, vpkdm-jsdoi-kv7bn-ra4yn-t2gu5-hvttd-4ubw5-g6oyh-ltplh-mw65j-bae] }', 'journald': {'custom': {'selinux_context': 'system_u:system_r:init_t:s0', 'stream_id': '9ff38823be774026954e933e151179e9'}}}, 'sort': [1649243172877]},
    def get_removed_nodes(self) -> Optional[List[NodeParams]]:
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

    #   {'@timestamp': '2022-04-06T11:06:21.570Z', 'message': '[Canister rwlgt-iiaaa-aaaaa-aaaaa-cai] [Registry Canister] do_add_nodes_to_subnet finished: AddNodesToSubnetPayload { subnet_id: fepls-j4bot-z6dp7-yrzwz-a5gtu-wkr5l-qle56-hwvxa-miyvw-65lc6-uae, node_ids: [uoels-4c3q4-lhton-kfjlf-e2j5w-gsg3m-7pan7-6ubmq-mgqva-4i3op-pae, vpkdm-jsdoi-kv7bn-ra4yn-t2gu5-hvttd-4ubw5-g6oyh-ltplh-mw65j-bae] }', 'syslog': {'identifier': 'orchestrator', 'priority': 6, 'facility': 3}, 'process': {'cmd': '/opt/ic/bin/canister_sandbox --embedder-config {"max_wasm_stack_size":5242880,"query_execution_threads":2,"max_globals":200,"max_functions":6000,"max_custom_sections":16,"max_custom_sections_size":1048576,"feature_flags":{"api_cycles_u128_flag":"Enabled","rate_limiting_of_debug_prints":"Enabled"}} rwlgt-iiaaa-aaaaa-aaaaa-cai', 'uid': 108, 'executable': '/opt/ic/bin/canister_sandbox', 'capabilites': '0', 'name': 'canister_sandbo', 'pid': 1009}, 'agent': {'version': '7.5.1', 'type': 'journalbeat', 'ephemeral_id': 'c32b94ad-c1c1-4742-82a7-d0a390b158bc', 'hostname': 'ip62001-4d78-40d-0-5000-cff-fe43-51cd', 'id': '716933ec-f7b2-4c18-b8e7-c33954759f9e'}, 'ecs': {'version': '1.1.0'}, 'host': {'id': '9b0d3813efd443ca9adaaeae0c4351cd', 'hostname': 'ip62001-4d78-40d-0-5000-cff-fe43-51cd', 'name': 'ip62001-4d78-40d-0-5000-cff-fe43-51cd', 'boot_id': '3a2713e18abf4212acce647f349ebace'}, 'journald': {'custom': {'selinux_context': 'system_u:system_r:init_t:s0', 'stream_id': '9ff38823be774026954e933e151179e9'}}, 'event': {'created': '2022-04-06T11:06:22.397Z'}, 'systemd': {'slice': 'system.slice', 'invocation_id': '4fbe6c1c49c445a78a4b1381b1959952', 'transport': 'stdout', 'cgroup': '/system.slice/ic-replica.service', 'unit': 'ic-replica.service'}, 'tags': ['system_test', 'hourly__node_reassignment_pot-2298485185']}, 'sort': [1649243181570]},
    def get_added_nodes(self) -> Optional[List[NodesubnetParams]]:
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


class ReplicaDoc(EsDoc):
    def __init__(self, repr):
        super().__init__(repr)
        assert self.is_replica(), f"Doc {str(self)} is not from the replica"

    def _log_entry(self):
        return self.parse_message()["log_entry"]

    def get_crate_module(self) -> Tuple[str, str]:
        le = self._log_entry()
        return le["crate_"], le["module"]

    def get_subnet_id(self) -> str:
        le = self._log_entry()
        return le["subnet_id"]

    def get_node_id(self) -> str:
        le = self._log_entry()
        return le["node_id"]

    def get_ipv6_prefixes(self) -> Optional[List[ipaddress.IPv6Network]]:
        le = self._log_entry()

        m = re.match(r".*ipv6_prefixes: \[(.*?)\].*", le["message"])
        if not m or len(m.groups()) < 1:
            return None
        else:
            prefixes_str = m.group(1)
            prefixes = prefixes_str.split(", ")
            prefixes = list(map(lambda ip: ip.strip('"'), prefixes))
            res: List[ipaddress.IPv6Network] = []
            for ip_str in prefixes:
                try:
                    ip = ipaddress.ip_network(ip_str, strict=False)
                except ValueError:
                    sys.stderr.write(f"WARNING: found invalid IPv6 data center mask: {ip_str}\n")
                    continue
                res.append(ip)
            return res

    # Consensus finalization
    class ConsensusFinalizationParams:
        """Data class"""

        def __init__(self, is_state_available: bool, is_key_available: bool):
            self.is_state_available = is_state_available
            self.is_key_available = is_key_available

    # Jan 20 09:04:28 medium05-1-2 orchestrator[1128]: {"log_entry":{"level":"INFO","utc_time":"2022-01-20T09:04:28.911Z","message":"Consensus finalized height: 149, state available: false, DKG key material available: true","crate_":"ic_consensus","module":"consensus","line":434,"node_id":"ycnxt-nn7hh-sow5h-fmdzh-gyy54-ilhxf-xubix-pwv2c-aie7o-whivf-lae","subnet_id":"62e3r-apw4o-mhxv3-xidd3-ngrxx-mnunc-xhlku-wkybu-yhq5o-mg2ou-3ae"}}
    def get_consensus_finalized_params(self) -> Optional[ConsensusFinalizationParams]:

        le = self._log_entry()
        lem = le["message"]
        if "Consensus finalized height" not in lem:
            return None
        else:
            m = re.match(".*state available: (false|true).*DKG key material available: (false|true).*", lem)
            if not m or len(m.groups()) < 2:
                sys.stderr.write(
                    f"WARNING: could not parse "
                    f"consensus_finalized_params in "
                    f"orchestrator document {self.id()}: {lem}\n"
                )
                return None
            else:
                return ReplicaDoc.ConsensusFinalizationParams(
                    is_state_available=(m.group(1) == "true"), is_key_available=(m.group(2) == "true")
                )

    # Jan 20 09:01:08 medium05-1-2 orchestrator[816]: {"log_entry":{"level":"INFO","utc_time":"2022-01-20T09:01:08.355Z","message":"Nodes zxdg4-ha7p6-dfvi3-eo5rs-rcvbi-pkuwu-scoy3-5lk6t-2bcvs-c3txn-xqe added","crate_":"ic_p2p","module":"download_management","line":1504,"node_id":"z3dw6-ej6yf-amnk2-4zclr-jmqtz-yhcew-273kp-tao44-7nf2y-rj5vx-yqe","subnet_id":"62e3r-apw4o-mhxv3-xidd3-ngrxx-mnunc-xhlku-wkybu-yhq5o-mg2ou-3ae"}}
    def get_p2p_node_params(self, verb: str) -> Optional[NodeParams]:
        le = self._log_entry()
        m = re.match("Nodes (.*?) %s" % verb, le["message"])
        if not m or len(m.groups()) < 1:
            return None
        else:
            node_id_str = m.group(1)  # e.g. "as2rc-bmlia-jxgj5-o2na4-skxu7-s3mdk-cweep-j4x2v-7ifz5-enkpq-7qe"
            if " " in node_id_str:
                sys.stderr.write(
                    f"WARNING: multiple nodes not yet supported"
                    f"in get_p2p_node_params; see doc {self.id()}: "
                    f"{node_id_str}\n"
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

        le = self._log_entry()
        m = re.match(r"Replica diverged at height (\d+)", le["message"])
        if not m or len(m.groups()) < 1:
            return None
        else:
            return ReplicaDoc.StateManagerReplicaDivergedParams(height=int(m.group(1)))

    class CatchUpPackageShare:
        """Data class"""

        def __init__(self, height: int):
            self.height = height

    # {"log_entry":{"level":"DEBUG","utc_time":"2021-11-25T11:40:22.079Z","message":"Proposing a CatchUpPackageShare at height 10","crate_":"ic_consensus","module":"catchup_package_maker","line":192,"node_id":"ctk2e-qe25c-zfjpi-s5ps2-uvvvk-uiofl-u3ab4-pryzz-tnyyv-egupe-cqe","subnet_id":"cpv7s-uecxn-abdz5-xkr3l-l5exk-f54in-66ebe-kyquf-ov2zm-wcq2m-nqe"}}
    def get_catchup_package_share_params(self) -> Optional[CatchUpPackageShare]:
        le = self._log_entry()
        lem = le["message"]
        m = re.match(r"Proposing a CatchUpPackageShare at height (\d+)", lem)
        if not m or len(m.groups()) < 1:
            return None
        else:
            return ReplicaDoc.CatchUpPackageShare(height=m.group(1))

    class ControlPlaneAcceptParams:
        """Data class"""

        def __init__(self, local_addr: str, flow: str, error: Optional[str] = None):
            self.local_addr = local_addr
            self.flow = flow
            self.error = error

    def get_control_plane_accept_params(self) -> Optional[ControlPlaneAcceptParams]:

        le = self._log_entry()
        m = re.match(r"ControlPlane::accept\(\): local_addr = (.*?), flow_tag = (.*?), error = (.*)", le["message"])
        if not m or len(m.groups()) != 3:
            return None
        else:
            return ReplicaDoc.ControlPlaneAcceptParams(local_addr=m.group(1), flow=m.group(2), error=quoted(m.group(3)))

    def get_control_plane_spawn_accept_task_params(self) -> Optional[ControlPlaneAcceptParams]:

        le = self._log_entry()
        m = re.match(r"ControlPlane::spawn_accept_task\(\): local_addr = (.*?), flow_tag = (.*)", le["message"])
        if not m or len(m.groups()) != 2:
            return None
        else:
            return ReplicaDoc.ControlPlaneAcceptParams(
                local_addr=m.group(1),
                flow=m.group(2),
            )

    class ControlPlaneAcceptTaskAbortedParams:
        """Data class"""

        def __init__(self, flow: str):
            self.flow = flow

    def get_control_plane_accept_task_aborted_params(self) -> Optional[ControlPlaneAcceptTaskAbortedParams]:

        le = self._log_entry()
        m = re.match("ControlPlane: accept task aborted: flow_tag = (.*)", le["message"])
        if not m or len(m.groups()) != 1:
            return None
        else:
            return ReplicaDoc.ControlPlaneAcceptTaskAbortedParams(flow=m.group(1))

    class ControlPlaneTlsServerHandshakeFailureParams:
        """Data class"""

        def __init__(self, node_id: str, node_addr: str, peer_addr: str, flow: str, error: str):
            self.node_id = node_id
            self.node_addr = node_addr
            self.peer_addr = peer_addr
            self.flow = flow
            self.error = error

    def get_control_plane_tls_server_handshake_failure_params(
        self,
    ) -> Optional[ControlPlaneTlsServerHandshakeFailureParams]:

        le = self._log_entry()
        m = re.match(
            r"ControlPlane::tls_server_handshake\(\) failed: "
            r"node = (.*?)/(.*?), flow_tag = (.*?), peer_addr = (.*?), "
            r"error = (.*)",
            le["message"],
        )
        if not m or len(m.groups()) != 5:
            return None
        else:
            # E.g., "ClientsEmpty" or
            # "HandshakeError { internal_error: \"(.*?)\" }"
            error_str = m.group(5)
            error_str = quoted(error_str)

            return ReplicaDoc.ControlPlaneTlsServerHandshakeFailureParams(
                node_id=m.group(1), node_addr=m.group(2), flow=m.group(3), peer_addr=m.group(4), error=error_str
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
        le = self._log_entry()
        lem: str = le["message"]
        marker = "Moved proposal Signed"
        if not lem.startswith(marker):
            return None
        return ReplicaDoc.extract_proposal_params(lem)

    #   {'_index': 'journalbeat-guestos-journal-7.5.1-2022.04.23', '_type': '_doc', '_id': 'L1sbVoABwsYIEpaybvZ0', '_score': None, '_source': {'@timestamp': '2022-04-23T11:07:32.279Z', 'process': {'uid': 116, 'cmd': '/opt/ic/bin/replica --replica-version=9697a4d7b226361429a921dcb745a8041d034832 --config-file=/run/ic-node/config/ic.json5 --catch-up-package=/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb --force-subnet=2wejy-h75eu-n5ll4-4nnpv-gi54q-jikx5-3nkje-24fjt-2x7jm-7mzek-eqe', 'executable': '/opt/ic/bin/replica', 'capabilites': '0', 'pid': 870, 'name': 'replica'}, 'event': {'created': '2022-04-23T11:07:33.076Z'}, 'systemd': {'invocation_id': '440441a9b4f24ec0a2d529ac8dabee02', 'transport': 'stdout', 'cgroup': '/system.slice/ic-replica.service', 'slice': 'system.slice', 'unit': 'ic-replica.service'}, 'agent': {'id': 'ee7bf411-daa9-4646-9a6f-c4dd5e2fe655', 'version': '7.5.1', 'type': 'journalbeat', 'ephemeral_id': '706a8795-4892-4662-b171-980000867b0e', 'hostname': 'blank'}, 'ecs': {'version': '1.1.0'}, 'host': {'hostname': 'ip62001-4d78-40d-0-5000-edff-fe82-d4a6', 'boot_id': '85ccbc34a3ef4a45bb67126be75510fe', 'name': 'blank', 'id': '5fa429fadf6d453d8b317e20ed82d4a6'}, 'journald': {'custom': {'stream_id': '123bb906484d4d03a17d095b9501fa03', 'selinux_context': 'system_u:system_r:ic_replica_t:s0'}}, 'message': '{"log_entry":{"level":"DEBUG","utc_time":"2022-04-23T11:07:32.279Z","message":"Moved proposal Signed { content: CryptoHash(0x37ae77534fb4e4752b9b9363d709d53d50dd88486b14212a19d894fa240a42bb), signature: BasicSignature { signature: BasicSig([225, 248, 222, 133, 64, 140, 77, 152, 193, 43, 74, 50, 54, 85, 251, 33, 219, 69, 164, 44, 160, 155, 245, 22, 3, 81, 87, 62, 71, 96, 35, 28, 3, 176, 176, 133, 92, 63, 150, 244, 223, 135, 245, 173, 3, 120, 163, 92, 197, 219, 66, 154, 94, 70, 25, 190, 231, 185, 54, 22, 28, 224, 77, 5]), signer: dsznh-fsrqe-5huly-3eezc-mp2d3-iud24-25dyx-pfgpk-2ybtw-gbzhw-fqe } } of rank Rank(7) to artifact pool","crate_":"ic_artifact_manager","module":"processors","line":370,"node_id":"qcnc6-m4ll5-thvmv-eevdg-ttdd6-y2frb-rjrxx-qcuam-hsrto-lk453-zqe","subnet_id":"2wejy-h75eu-n5ll4-4nnpv-gi54q-jikx5-3nkje-24fjt-2x7jm-7mzek-eqe"}}', 'syslog': {'identifier': 'orchestrator', 'priority': 6, 'facility': 3}, 'tags': ['system_test', 'nightly__two_third_latency_pot-arshavir-zh1-spm34_zh1_dfinity_network-1650711811']}, 'sort': [1650712052279]}
    # debug!(
    #     self.log,
    #     "Added proposal {:?} of rank {:?} to artifact pool", p, rank
    # ); // https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/artifact_manager/src/processors.rs?L357
    # debug!(
    #     self.log,
    #     "Moved proposal {:?} of rank {:?} to artifact pool", p, rank
    # ); // https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/artifact_manager/src/processors.rs?L370
    def get_validated_block_proposal_params(self, verb: str) -> Optional[ProposalParams]:

        le = self._log_entry()
        lem: str = le["message"]
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

    # Jan 20 09:03:22 medium05-1-2 orchestrator[817]: {"log_entry":{"level":"INFO","utc_time":"2022-01-20T09:03:22.743Z","message":"deliver batch 106 for block_hash \"3b6f4fd74bae8155d7f6cf8213da4f65ae9d6a28a814dccf712c8e937123d557\"","crate_":"ic_consensus","module":"batch_delivery","line":150,"node_id":"zxdg4-ha7p6-dfvi3-eo5rs-rcvbi-pkuwu-scoy3-5lk6t-2bcvs-c3txn-xqe","subnet_id":"62e3r-apw4o-mhxv3-xidd3-ngrxx-mnunc-xhlku-wkybu-yhq5o-mg2ou-3ae"}}
    def get_batch_delivery_params(self) -> Optional[BatchDeliveryParams]:
        le = self._log_entry()
        m = re.match('.*block_hash "(.*?)".*', le["message"])
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

    # 'message': '{"log_entry":{"level":"DEBUG","utc_time":"2022-02-13T11:05:01.863Z","message":"Finalized height","crate_":"ic_consensus","module":"batch_delivery","line":81,"node_id":"cpd7c-6rrmi-s34or-7tihv-byeqs-22wtz-u3jl7-7rmmm-k4l3z-f3ak4-4ae","subnet_id":"3yr5l-fecjk-i4yxq-fsukl-zerdg-jqlnr-xsqrs-j65jq-w2246-4qhzl-wqe","consensus":{"height":1,"hash":"e36232694f0ce7f0e13e98ec64e4db26f04a3e9d7bc07791fb7b2eacceec2b44"}}}'
    def get_batch_delivery_consensus_params(self) -> Optional[ConsensusParams]:
        le = self._log_entry()
        if "consensus" in le:
            con = le["consensus"]
            return ReplicaDoc.ConsensusParams(
                height=con["height"], hash=con["hash"], replica_version=con["replica_version"]
            )
        else:
            return None

    class UnusualLogLevelParams:
        """Data class"""

        def __init__(self, level: str, message: str):
            self.level = level
            self.message = message

    def get_unusual_log_level_event_params(self) -> Optional[UnusualLogLevelParams]:

        le = self._log_entry()
        lel = le["level"]
        lem = le["message"]
        if lel != "CRITICAL" and lel != "ERROR":
            return None
        else:
            return ReplicaDoc.UnusualLogLevelParams(level=lel, message=quoted(lem))
