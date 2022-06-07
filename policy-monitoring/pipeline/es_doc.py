import ipaddress
import json
import re
import sys
from datetime import datetime
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple


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

    #   {'_index': 'journalbeat-guestos-journal-7.5.1-2022.05.21', '_type': '_doc', '_id': 'zNRS54ABwsYIEpayoTe7', '_score': None, '_source': {'@timestamp': '2022-05-21T15:53:11.827Z', 'syslog': {'facility': 3, 'priority': 6, 'identifier': 'orchestrator'}, 'ecs': {'version': '1.1.0'}, 'agent': {'id': '1fcdbbe9-6065-4960-a1c6-712323b42e54', 'version': '7.5.1', 'type': 'journalbeat', 'ephemeral_id': '80e3ea00-a94a-4964-8844-ae01c6c42173', 'hostname': 'blank'}, 'message': '[Canister rwlgt-iiaaa-aaaaa-aaaaa-cai] [Registry] do_create_subnet: {payload: CreateSubnetPayload { node_ids: [5clia-sq75b-4svqq-b6nod-dbqla-5ukfb-74azh-fb3yx-jyww2-iuzpf-iqe, 75oko-7ya4i-bdbpu-xapf5-miuaf-trflg-opt36-kj6ko-xm6mq-wud6h-tqe, dt563-psj4o-mke5u-xyfmx-c6gj7-ig63f-ykd2f-ec2u4-m2dsb-jt6b6-zae, vxacy-g2zq6-ygrgg-pfqb4-wxe4k-ibxiy-zlp5k-ckcro-2ffa2-dh6s4-3ae], subnet_id_override: None, ingress_bytes_per_block_soft_cap: 2097152, max_ingress_bytes_per_message: 2097152, max_ingress_messages_per_block: 1000, max_block_payload_size: 4194304, unit_delay_millis: 1000, initial_notary_delay_millis: 600, replica_version_id: "0b2a151dc582640a6ca8c967fc73606f95411bc5", dkg_interval_length: 499, dkg_dealings_per_block: 1, gossip_max_artifact_streams_per_peer: 20, gossip_max_chunk_wait_ms: 15000, gossip_max_duplicity: 1, gossip_max_chunk_size: 4096, gossip_receive_check_cache_size: 5000, gossip_pfn_evaluation_period_ms: 1000, gossip_registry_poll_period_ms: 3000, gossip_retransmission_request_ms: 60000, advert_best_effort_percentage: Some(20), start_as_nns: false, subnet_type: Application, is_halted: false, max_instructions_per_message: 5000000000, max_instructions_per_round: 7000000000, max_instructions_per_install_code: 200000000000, features: SubnetFeatures { ecdsa_signatures: false, canister_sandboxing: false, http_requests: false, bitcoin: None }, max_number_of_canisters: 4, ssh_readonly_access: [], ssh_backup_access: [], ecdsa_config: None }, subnet_id: cbcun-icjyv-6gyoy-5elnl-fmww6-ggtam-62qvn-stqwc-4bgs7-y5wwa-hae}', 'event': {'created': '2022-05-21T15:53:12.900Z'}, 'systemd': {'invocation_id': '45b97258c4534a1ea14f1c6141c827d2', 'transport': 'stdout', 'cgroup': '/system.slice/ic-replica.service', 'slice': 'system.slice', 'unit': 'ic-replica.service'}, 'journald': {'custom': {'stream_id': 'b077a69578af4354ab234404ac0d74a2', 'selinux_context': 'system_u:system_r:init_t:s0'}}, 'tags': ['system_test', 'hourly__create_subnet-martin-zh1-spm22_zh1_dfinity_network-1653148250'], 'process': {'pid': 1002, 'cmd': '/opt/ic/bin/canister_sandbox --embedder-config {"max_wasm_stack_size":5242880,"query_execution_threads":2,"max_globals":300,"max_functions":7000,"max_custom_sections":16,"max_custom_sections_size":1048576,"feature_flags":{"api_cycles_u128_flag":"Enabled","rate_limiting_of_debug_prints":"Enabled"}} rwlgt-iiaaa-aaaaa-aaaaa-cai', 'executable': '/opt/ic/bin/canister_sandbox', 'uid': 108, 'name': 'canister_sandbo', 'capabilites': '0'}, 'host': {'hostname': 'ip62001-4d78-40d-0-5000-4aff-fec4-b00c', 'boot_id': '4462ba9918f04696a563328bc94ad4a6', 'id': 'fdf362f8dc2142f2bf6c64164ac4b00c', 'name': 'blank'}}, 'sort': [1653148391827]},
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

    #   {'_index': 'journalbeat-guestos-journal-7.5.1-2022.05.21', '_type': '_doc', '_id': 'YLZb54ABKhMW8WgQHcp6', '_score': None, '_source': {'@timestamp': '2022-05-21T16:02:28.020Z', 'journald': {'custom': {'selinux_context': 'system_u:system_r:init_t:s0', 'stream_id': '67b1da3602d14784b7e8805b8c9e12a7'}}, 'event': {'created': '2022-05-21T16:02:28.872Z'}, 'systemd': {'transport': 'stdout', 'cgroup': '/system.slice/ic-replica.service', 'unit': 'ic-replica.service', 'slice': 'system.slice', 'invocation_id': '971b70f079ac4560b1ff1e0a6b98051f'}, 'message': '[Canister rwlgt-iiaaa-aaaaa-aaaaa-cai] [Registry] do_update_subnet: UpdateSubnetPayload { subnet_id: basbk-ayycd-cngac-7mqut-ffjiq-z7lxq-wyq2s-4uof3-nrj7i-nhitq-xqe, max_ingress_bytes_per_message: None, max_ingress_messages_per_block: None, max_block_payload_size: None, unit_delay_millis: None, initial_notary_delay_millis: None, dkg_interval_length: None, dkg_dealings_per_block: None, max_artifact_streams_per_peer: None, max_chunk_wait_ms: None, max_duplicity: None, max_chunk_size: None, receive_check_cache_size: None, pfn_evaluation_period_ms: None, registry_poll_period_ms: None, retransmission_request_ms: None, advert_best_effort_percentage: None, set_gossip_config_to_default: false, start_as_nns: None, subnet_type: None, is_halted: None, max_instructions_per_message: None, max_instructions_per_round: None, max_instructions_per_install_code: None, features: None, ecdsa_config: Some(EcdsaConfig { quadruples_to_create_in_advance: 10, key_ids: [EcdsaKeyId { curve: Secp256k1, name: "secp256k1" }] }), ecdsa_key_signing_enable: None, ecdsa_key_signing_disable: None, max_number_of_canisters: None, ssh_readonly_access: None, ssh_backup_access: None }', 'process': {'uid': 116, 'pid': 1038, 'cmd': '/opt/ic/bin/canister_sandbox --embedder-config {"max_wasm_stack_size":5242880,"query_execution_threads":2,"max_globals":300,"max_functions":7000,"max_custom_sections":16,"max_custom_sections_size":1048576,"feature_flags":{"api_cycles_u128_flag":"Enabled","rate_limiting_of_debug_prints":"Enabled"}} rwlgt-iiaaa-aaaaa-aaaaa-cai', 'capabilites': '0', 'name': 'canister_sandbo', 'executable': '/opt/ic/bin/canister_sandbox'}, 'syslog': {'identifier': 'orchestrator', 'priority': 6, 'facility': 3}, 'tags': ['system_test', 'hourly__tecdsa_signature_same_subnet_pot-martin-zh1-spm22_zh1_dfinity_network-1653148721'], 'agent': {'ephemeral_id': '242319be-c20b-4897-8498-973f1e4a804f', 'hostname': 'blank', 'id': '36f1ce14-c1d3-4886-a62f-5486ef2f3d57', 'version': '7.5.1', 'type': 'journalbeat'}, 'ecs': {'version': '1.1.0'}, 'host': {'id': 'e5eb5c52b1ec49df8f107283b9820c6f', 'name': 'blank', 'boot_id': 'fef8d2207a374ce0906a5984298c968d', 'hostname': 'ip62001-4d78-40d-0-5000-b9ff-fe82-c6f'}}, 'sort': [1653148948020]},
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

    #  {'_index': 'journalbeat-guestos-journal-7.5.1-2022.05.21', '_type': '_doc', '_id': 'ydZa54ABwsYIEpayCUo7', '_score': None, '_source': {'@timestamp': '2022-05-21T16:01:15.873Z', 'message': '[Canister rwlgt-iiaaa-aaaaa-aaaaa-cai] [Registry] do_remove_nodes_from_subnet started: RemoveNodesFromSubnetPayload { node_ids: [35acm-i34bc-jsxcs-drpqs-4ux4k-7le55-sz4x5-bivjl-7nhbt-gplof-mqe, fimce-f3l6q-hizba-i5si4-ivanz-2ulhs-r5hou-vvq4y-z7v6t-2fajy-vae] }', 'ecs': {'version': '1.1.0'}, 'event': {'created': '2022-05-21T16:01:18.151Z'}, 'host': {'id': '83b51a5670ff4fba971fd4305aa7cf13', 'name': 'blank', 'boot_id': '347e3b33b60a4ea2979fa52a098d1bcb', 'hostname': 'ip62001-4d78-40d-0-5000-5aff-fea7-cf13'}, 'systemd': {'slice': 'system.slice', 'transport': 'stdout', 'invocation_id': '231656c813ff4e9eb6e5857a6d3ec884', 'cgroup': '/system.slice/ic-replica.service', 'unit': 'ic-replica.service'}, 'process': {'cmd': '/opt/ic/bin/canister_sandbox --embedder-config {"max_wasm_stack_size":5242880,"query_execution_threads":2,"max_globals":300,"max_functions":7000,"max_custom_sections":16,"max_custom_sections_size":1048576,"feature_flags":{"api_cycles_u128_flag":"Enabled","rate_limiting_of_debug_prints":"Enabled"}} rwlgt-iiaaa-aaaaa-aaaaa-cai', 'name': 'canister_sandbo', 'pid': 1049, 'uid': 108, 'capabilites': '0', 'executable': '/opt/ic/bin/canister_sandbox'}, 'syslog': {'priority': 6, 'facility': 3, 'identifier': 'orchestrator'}, 'journald': {'custom': {'selinux_context': 'system_u:system_r:init_t:s0', 'stream_id': 'ed4ba4bf015949ccaf8c165a8f954a6d'}}, 'tags': ['system_test', 'hourly__tecdsa_remove_nodes_pot-martin-zh1-spm22_zh1_dfinity_network-1653148721'], 'agent': {'version': '7.5.1', 'type': 'journalbeat', 'ephemeral_id': 'aef92fa2-435b-4005-b5b7-60f8f257f116', 'hostname': 'blank', 'id': '542aea65-327b-40b5-894b-647ea3352338'}}, 'sort': [1653148875873]},
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

    #   {'_index': 'journalbeat-guestos-journal-7.5.1-2022.05.21', '_type': '_doc', '_id': 'w9Za54ABwsYIEpayEkwt', '_score': None, '_source': {'@timestamp': '2022-05-21T16:01:20.058Z', 'systemd': {'slice': 'system.slice', 'transport': 'stdout', 'cgroup': '/system.slice/ic-replica.service', 'unit': 'ic-replica.service', 'invocation_id': 'a1a9012e675b4f518a1f4a05e1416ddc'}, 'host': {'boot_id': '55f99aae5bdb4f7cb7778048b2dd8cd9', 'id': '0d28be519f6c47359a90fd3f849976b9', 'hostname': 'ip62001-4d78-40d-0-5000-84ff-fe99-76b9', 'name': 'blank'}, 'tags': ['system_test', 'hourly__tecdsa_add_nodes_pot-martin-zh1-spm22_zh1_dfinity_network-1653148721'], 'agent': {'id': 'd3cc0252-2624-48d1-8433-660ff1467c40', 'version': '7.5.1', 'type': 'journalbeat', 'ephemeral_id': '33d8b5a1-08d2-4baf-ae2e-17016b422162', 'hostname': 'blank'}, 'message': '[Canister rwlgt-iiaaa-aaaaa-aaaaa-cai] [Registry] do_add_nodes_to_subnet started: AddNodesToSubnetPayload { subnet_id: zqbvp-jbpwl-jblgr-2pash-5nbs4-jzyt4-uxc4q-acsct-ynxhm-vlorr-vqe, node_ids: [3qzji-sp6j5-6clae-2tjtq-qvauh-qcnku-cq5xc-lhffl-qlwgg-63plk-cqe, ntjoz-a5fia-5s6q5-uz2ir-4lnhu-66er6-qtm54-ayc7f-4ejj6-ih5rz-tae, p3sku-hq32u-bez5v-a7w46-umfwh-ig5dv-cbdjh-xmhgj-43eab-ihuui-yqe] }', 'ecs': {'version': '1.1.0'}, 'journald': {'custom': {'selinux_context': 'system_u:system_r:init_t:s0', 'stream_id': '467b55e3a80549eab27d52955f6adbd0'}}, 'event': {'created': '2022-05-21T16:01:20.442Z'}, 'process': {'capabilites': '0', 'pid': 1017, 'name': 'canister_sandbo', 'executable': '/opt/ic/bin/canister_sandbox', 'uid': 116, 'cmd': '/opt/ic/bin/canister_sandbox --embedder-config {"max_wasm_stack_size":5242880,"query_execution_threads":2,"max_globals":300,"max_functions":7000,"max_custom_sections":16,"max_custom_sections_size":1048576,"feature_flags":{"api_cycles_u128_flag":"Enabled","rate_limiting_of_debug_prints":"Enabled"}} rwlgt-iiaaa-aaaaa-aaaaa-cai'}, 'syslog': {'priority': 6, 'facility': 3, 'identifier': 'orchestrator'}}, 'sort': [1653148880058]},
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

    def get_log_entry_message(self):
        le = self._log_entry()
        return le["message"]

    def get_crate_module(self) -> Tuple[str, str]:
        le = self._log_entry()
        return le["crate_"], le["module"]

    def get_subnet_id(self) -> str:
        le = self._log_entry()
        return le["subnet_id"]

    def get_subnet_type(self) -> Optional[Tuple[str, str]]:
        m = re.search(
            r"{subnet_record: Registry subnet record SubnetRecord {.*subnet_type: ([A-Za-z]*),.*}, subnet_id: ([a-z0-9-]*)}",
            self.get_log_entry_message(),
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

    #   {'_index': 'journalbeat-guestos-journal-7.5.1-2022.05.26', '_type': '_doc', '_id': 'vJT2AIEBwsYIEpaypvXf', '_score': None, '_source': {'@timestamp': '2022-05-26T15:22:39.304Z', 'ecs': {'version': '1.1.0'}, 'agent': {'id': 'da9e6660-f5f6-49e8-80ff-73160afdea22', 'version': '7.5.1', 'type': 'journalbeat', 'ephemeral_id': '84239e09-a35b-4e16-b80a-e51f4b97ba1a', 'hostname': 'blank'}, 'process': {'uid': 108, 'pid': 878, 'name': 'replica', 'capabilites': '0', 'executable': '/opt/ic/bin/replica', 'cmd': '/opt/ic/bin/replica --replica-version=48e7a07bafda4afdabec202e38e2495cf01b25dc --config-file=/run/ic-node/config/ic.json5 --catch-up-package=/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb --force-subnet=mg46u-46ckl-x23kq-jezmy-jryfy-ltc4r-sff6p-xjkte-i2as4-q6fv3-gae'}, 'host': {'boot_id': 'cfb9b591a3c248db9192a09ac2eb7538', 'hostname': 'ip62001-4d78-40d-0-5000-20ff-fed1-a380', 'name': 'blank', 'id': '3e14f12542c34adbbb49cb3020d1a380'}, 'systemd': {'invocation_id': '91a04d5acb324611908b23c025c84f96', 'slice': 'system.slice', 'transport': 'stdout', 'cgroup': '/system.slice/ic-replica.service', 'unit': 'ic-replica.service'}, 'message': '{"log_entry":{"level":"INFO","utc_time":"2022-05-26T15:22:39.304Z","message":"Nodes pmqbk-2ih5f-bdbp6-lcssw-tli3p-nl2lu-t2vh7-jvvc2-xg5sf-wufl2-rqe added","crate_":"ic_p2p","module":"download_management","line":1480,"node_id":"3s3k7-ap7sp-277ph-w3gem-m5i2g-dmw6f-uddym-deqe3-2ibok-u2azb-2qe","subnet_id":"mg46u-46ckl-x23kq-jezmy-jryfy-ltc4r-sff6p-xjkte-i2as4-q6fv3-gae"}}', 'tags': ['system_test', 'hourly__node_reassignment_pot-martin-zh1-spm22_zh1_dfinity_network-1653578467'], 'journald': {'custom': {'stream_id': 'fff52fbfcaa84b3bac6b5d165f559522', 'selinux_context': 'system_u:system_r:ic_replica_t:s0'}}, 'event': {'created': '2022-05-26T15:22:39.462Z'}, 'syslog': {'priority': 6, 'identifier': 'orchestrator', 'facility': 3}}, 'sort': [1653578559304]}
    #   {'_index': 'journalbeat-guestos-journal-7.5.1-2022.05.26', '_type': '_doc', '_id': 'vpj5AIEBwsYIEpayjce6', '_score': None, '_source': {'@timestamp': '2022-05-26T15:26:02.663Z', 'message': '{"log_entry":{"level":"INFO","utc_time":"2022-05-26T15:26:02.663Z","message":"Nodes 5kbyr-a7hsu-6hmcc-72auv-lqgnh-yq3bs-itfea-xblyu-wjhp2-l3wg7-6qe removed","crate_":"ic_p2p","module":"download_management","line":1512,"node_id":"xkiab-vhf44-vczgd-yob6x-qncey-rl2ds-joc6w-6mwfl-cgnsx-a75ok-eae","subnet_id":"upygj-j6xmw-azx5r-24q2d-6mwdu-si5jx-p7skv-w3mex-h772r-f52ja-fqe"}}', 'journald': {'custom': {'selinux_context': 'system_u:system_r:ic_replica_t:s0', 'stream_id': '06c56b9df8bf41578e9360baa9e552b6'}}, 'ecs': {'version': '1.1.0'}, 'agent': {'id': '89d8aed6-f02a-4a81-bf9d-f2292d65f6ca', 'version': '7.5.1', 'type': 'journalbeat', 'ephemeral_id': '500cff48-6b55-489b-93f7-8e837a011ae8', 'hostname': 'blank'}, 'tags': ['system_test', 'hourly__node_reassignment_pot-martin-zh1-spm22_zh1_dfinity_network-1653578467'], 'systemd': {'unit': 'ic-replica.service', 'invocation_id': '524e536cf54a4b759d88a3ced2f450d9', 'cgroup': '/system.slice/ic-replica.service', 'slice': 'system.slice', 'transport': 'stdout'}, 'host': {'boot_id': 'd377747e599d4c45ad00bc57c8399ce1', 'hostname': 'ip62001-4d78-40d-0-5000-dff-fe01-969f', 'name': 'blank', 'id': 'a04ab48f0d39481683fbb6570d01969f'}, 'process': {'capabilites': '0', 'pid': 873, 'cmd': '/opt/ic/bin/replica --replica-version=48e7a07bafda4afdabec202e38e2495cf01b25dc --config-file=/run/ic-node/config/ic.json5 --catch-up-package=/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb --force-subnet=upygj-j6xmw-azx5r-24q2d-6mwdu-si5jx-p7skv-w3mex-h772r-f52ja-fqe', 'name': 'replica', 'executable': '/opt/ic/bin/replica', 'uid': 116}, 'syslog': {'identifier': 'orchestrator', 'facility': 3, 'priority': 6}, 'event': {'created': '2022-05-26T15:26:02.687Z'}}, 'sort': [1653578762663]},
    def get_p2p_node_params(self, verb: str) -> Optional[NodeParams]:
        le = self._log_entry()
        m = re.match("Nodes (.*?) %s" % verb, le["message"])
        if not m or len(m.groups()) < 1:
            return None
        else:
            node_id_str = m.group(1)
            if " " in node_id_str:
                sys.stderr.write(
                    f"WARNING: multiple nodes not yet supported "
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

    #   {'_index': 'journalbeat-guestos-journal-7.5.1-2022.05.30', '_type': '_doc', '_id': 'Z8S1FoEBKhMW8WgQsrY0', '_score': None, '_source': {'@timestamp': '2022-05-30T20:43:32.564Z', 'host': {'boot_id': 'a1b3d27c41cb4646bd959c6afb060f56', 'hostname': 'ip62001-4d78-40d-0-5000-eeff-fe2c-7449', 'name': 'ip62001-4d78-40d-0-5000-eeff-fe2c-7449', 'id': '7afdd2ccb04a411c9f1034a8ee2c7449'}, 'syslog': {'identifier': 'orchestrator', 'facility': 3, 'priority': 6}, 'journald': {'custom': {'stream_id': '8ae47b75323b4aaf952e3727c42a6b72', 'selinux_context': 'system_u:system_r:ic_replica_t:s0'}}, 'tags': ['system_test', 'hourly__node_reassignment_pot-martin-zh1-spm22_zh1_dfinity_network-1653943283'], 'systemd': {'slice': 'system.slice', 'unit': 'ic-replica.service', 'invocation_id': 'a4307262e55e40489d040d1bab983171', 'cgroup': '/system.slice/ic-replica.service', 'transport': 'stdout'}, 'process': {'cmd': '/opt/ic/bin/replica --replica-version=369ceb3f8893c8bafea9218da020b629425b6c99 --config-file=/run/ic-node/config/ic.json5 --catch-up-package=/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb --force-subnet=42a4b-yeccf-nwbcg-m6lx7-wa7ce-j44jz-4xpxr-etzzk-mphai-rsg2d-dae', 'name': 'replica', 'executable': '/opt/ic/bin/replica', 'capabilites': '0', 'uid': 116, 'pid': 837}, 'message': '{"log_entry":{"level":"DEBUG","utc_time":"2022-05-30T20:43:32.563Z","message":"replica ReplicaVersion { version_id: \\"369ceb3f8893c8bafea9218da020b629425b6c99\\" } delivered batch 1 for block_hash \\"0c40bafcb91b67ca31f1a4c1cd84c3e4fb90c129fe0ed67ba1380593ddb71398\\"","crate_":"ic_consensus","module":"batch_delivery","line":170,"node_id":"lqyhp-6xpyo-tncs6-bj7nk-x3zsy-a3cc3-s4twf-pp4qq-2a3hr-6fdnf-nae","subnet_id":"42a4b-yeccf-nwbcg-m6lx7-wa7ce-j44jz-4xpxr-etzzk-mphai-rsg2d-dae"}}', 'event': {'created': '2022-05-30T20:43:32.898Z'}, 'ecs': {'version': '1.1.0'}, 'agent': {'type': 'journalbeat', 'ephemeral_id': '91c0a6ca-6c7e-4033-afcb-c7bca1572757', 'hostname': 'ip62001-4d78-40d-0-5000-eeff-fe2c-7449', 'id': '1929297b-dfd4-423f-a72c-788bfcadc5f8', 'version': '7.5.1'}}, 'sort': [1653943412564]},
    def get_batch_delivery_params(self) -> Optional[BatchDeliveryParams]:
        le = self._log_entry()
        m = re.match('.*block_hash \\"(.*?)\\".*', le["message"])
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
