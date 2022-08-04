import pprint
from pathlib import Path
from typing import Set

from pipeline.artifact_manager import ArtifactManager
from pipeline.global_infra import GlobalInfra

GLOBINFRA_DIR = Path(__file__).absolute().parent.joinpath("global_infra_resources")
ORIGINAL_GLOBINFRA_FILE = GLOBINFRA_DIR.joinpath("mock_global_infra.yaml")
FIRST_GLOBINFRA_FILE = GLOBINFRA_DIR.joinpath("mock_global_infra_1.yaml")
SECOND_GLOBINFRA_FILE = GLOBINFRA_DIR.joinpath("mock_global_infra_2.yaml")

IC_REGEDIT_SNAPSHOT = GLOBINFRA_DIR.joinpath("reg-snap.json")
IC_REGEDIT_SNAPSHOT_REPRO = GLOBINFRA_DIR.joinpath("reg-snap-repro.yaml")


def cleanup():
    FIRST_GLOBINFRA_FILE.unlink(missing_ok=True)
    SECOND_GLOBINFRA_FILE.unlink(missing_ok=True)
    IC_REGEDIT_SNAPSHOT_REPRO.unlink(missing_ok=True)


def load_global_infra_yaml(fin: Path):
    res = GlobalInfra.fromYamlFile(input_file=fin)
    res.source = "<omitted_for_testing>"
    return res


def load_gloabl_infra_json(fin: Path):
    return GlobalInfra.fromIcRegeditSnapshotFile(fin)


def dump_global_infra_yaml(ginfra, fout: Path):
    ArtifactManager.save_yaml(ginfra.to_dict(), fout)


def assert_eq(a, b) -> None:
    a1, b1 = pprint.pformat(a), pprint.pformat(b)
    assert a1 == b1, f"{a1}\ndid not equal\n{b1}"


def assert_in(a, A) -> None:
    assert a in A, f"{str(a)}\nis not a member of\n{str(A)}"


def assert_subset(A: Set, B: Set) -> None:
    assert A.issubset(
        B
    ), f"Set A with {len(A)} elements is not a subset of set B with {len(B)} elements. A\\B has {len(A.difference(B))} elements"


# Test A: Global Infra Yaml I/O is idempotent
ginfra_1 = load_global_infra_yaml(ORIGINAL_GLOBINFRA_FILE)
dump_global_infra_yaml(ginfra_1, FIRST_GLOBINFRA_FILE)

ginfra_2 = load_global_infra_yaml(FIRST_GLOBINFRA_FILE)
dump_global_infra_yaml(ginfra_2, SECOND_GLOBINFRA_FILE)

ginfra_3 = load_global_infra_yaml(SECOND_GLOBINFRA_FILE)

x = pprint.pformat(ginfra_1.to_dict())
y = pprint.pformat(ginfra_2.to_dict())
z = pprint.pformat(ginfra_3.to_dict())
assert x == y == z, (
    f"Original GlobalInfra object:\n" f"{x}\n" f"did not match reconstructed GlobalInfra object:\n" f"{y}"
)
print("Global Infra Yaml I/O idempotentcy test passed.")


# Test B: Global Infra snapshots from ic-regedit
ginfra_4 = load_gloabl_infra_json(IC_REGEDIT_SNAPSHOT)
dump_global_infra_yaml(ginfra_4, IC_REGEDIT_SNAPSHOT_REPRO)

assert_eq(len(ginfra_4.known_hosts), len(ginfra_4.host_addr_to_node_id_map))
assert_eq(set(ginfra_4.node_id_to_host_map.keys()), set(ginfra_4.host_addr_to_node_id_map.values()))
assert_eq(len(set(ginfra_4.original_subnet_membership.values())), len(ginfra_4.original_subnet_types))


assert_eq(len(ginfra_4.in_subnet_relations.keys()), len(ginfra_4.original_subnet_types))
assert_in(
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe", ginfra_4.original_subnet_membership.values()
)

nodes_from_memberships = set(
    map(lambda x: x[1], [node_id for node_ids in ginfra_4.in_subnet_relations.values() for node_id in node_ids])
)
nodes_from_node_records = set(ginfra_4.host_addr_to_node_id_map.values())

assert_subset(nodes_from_memberships, nodes_from_node_records)
assert_subset(set(ginfra_4.original_subnet_membership.keys()), ginfra_4.host_addr_to_node_id_map.values())

print("Global Infra from ic-regedit test passed.")

cleanup()
