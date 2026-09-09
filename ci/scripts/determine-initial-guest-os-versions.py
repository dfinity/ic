import json
import sys
from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict, cast
from urllib.request import Request, urlopen

ROLLOUT_DASHBOARD_ENDPOINT = "https://rollout-dashboard.dm1-dre1.dfinity.network/api/v1/rollouts"
PUBLIC_DASHBOARD_ENDPOINT = "https://ic-api.internetcomputer.org/api/v3/subnets?format=json"

# The NNS subnet.  Cloud engine subnets follow the NNS's GuestOS version, so we
# qualify them starting from whatever version the NNS subnet is running.
NNS_SUBNET_ID = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
# Value of PDSubnet["subnet_type"] identifying a cloud engine subnet.
# Keep in sync with subnet_type_as_string() in
# rs/canonical_state/src/lazy_tree_conversion.rs .
CLOUD_ENGINE_SUBNET_TYPE = "cloud_engine"

# Key definitions
EXECUTED_TIMESTAMP_SECONDS = "executed_timestamp_seconds"
REPLICA_VERSIONS = "replica_versions"
REPLICA_VERSION_ID = "replica_version_id"
SUBNETS = "subnets"


# Minimal subset of API structure needed for rollout dashboard.
# Always keep me in sync with https://github.com/dfinity/dre-airflow/blob/main/rollout-dashboard/server/src/types.rs
# We do not expect to change the API in ways that break code.
class SubnetRolloutState(Enum):
    error = "error"
    predecessor_failed = "predecessor_failed"
    pending = "pending"
    waiting = "waiting"
    proposing = "proposing"
    waiting_for_election = "waiting_for_election"
    waiting_for_adoption = "waiting_for_adoption"
    waiting_for_alerts_gone = "waiting_for_alerts_gone"
    complete = "complete"
    unknown = "unknown"


class Subnet(TypedDict):
    subnet_id: str
    git_revision: str
    state: SubnetRolloutState


class Batch(TypedDict):
    subnets: List[Subnet]
    # The following three are dates but they are ISO UTF Z,
    # so they sort alphabetically.  Heh.
    planned_start_time: str
    actual_start_time: Optional[str]
    end_time: Optional[str]


class RolloutState(Enum):
    complete = "complete"
    failed = "failed"
    preparing = "preparing"
    upgrading_subnets = "upgrading_subnets"
    upgrading_unassigned_nodes = "upgrading_unassigned_nodes"
    waiting = "waiting"
    problem = "problem"


class Rollout(TypedDict):
    name: str
    state: RolloutState
    batches: Dict[str, Batch]


# Minimal subset of API structure needed for public dashboard.
# Swagger for the public dashboard API: https://ic-api.internetcomputer.org/api/v3/swagger .
class PDReplicaVersion(TypedDict):
    executed_timestamp_seconds: Optional[int]
    proposal_id: str  # really an int
    replica_version_id: str


class PDSubnet(TypedDict):
    replica_versions: List[PDReplicaVersion]
    subnet_id: str
    subnet_type: str


class PDSubnetsResponse(TypedDict):
    subnets: List[PDSubnet]


# Result of fetch_versions_from_public_dashboard(): the version currently
# running on the subnet plus its subnet type (used to identify cloud engines).
class PublicDashboardSubnet(TypedDict):
    replica_version_id: str
    subnet_type: str


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def eprint_fmt(str, *args):
    return  # remove me to get some real action
    print((str % args) if args else str, file=sys.stderr)


def request_json(url: str) -> Any:
    req = Request(url, headers={"User-Agent": "python"})
    resp = urlopen(req, timeout=15)
    if resp.status != 200:
        try:
            data = resp.read()
        except Exception:
            data = None
        raise RuntimeError(
            "Non-200 HTTP response (%s) from %s: %s"
            % (resp.status, url, data[:160] if data else "(no data in response)")
        )
    return json.load(resp)


def fetch_versions_from_rollout_dashboard():  # type: () -> dict[str, str]
    """
    Fetch data from rollout dashboard

    Panics if the parsed data is not in the expected format.
    Returns an empty dict if the action is retriable.
    """
    url = ROLLOUT_DASHBOARD_ENDPOINT
    try:
        rollouts = cast(List[Rollout], request_json(url))
    except Exception as e:
        eprint(f"Error fetching / decoding data from {url}: {e}.  Returning no versions.")
        return dict()

    # The value of the dict entry is datestring, git revision.
    subnet_to_revision = {}  # type: dict[str, list[tuple[str, str]]]

    for rollout in reversed(rollouts):  # Oldest to newest
        for batch_num_ignored, batch in rollout["batches"].items():
            for subnet in batch["subnets"]:
                if subnet["state"] in (SubnetRolloutState.error, SubnetRolloutState.predecessor_failed):
                    # This subnet failed?  We ignore it, because it could not have been upgraded.
                    # There is a minor corner case where the subnet may be in error (not predecessor_failed)
                    # but a proposal has been filed *and* approved, which means the subnet is in fact
                    # already carrying the git revision stated by the subnet object.
                    # We could expose the proposal number and its state in the rollout dashboard API
                    # (this information is stored by Airflow and known to it) to settle this uncertainty,
                    # but I'm not sure it's worth the effort.
                    eprint_fmt(
                        "Version %s targeting subnet %s in rollout %s is %s, disregarding",
                        subnet["git_revision"],
                        subnet["subnet_id"],
                        rollout["name"],
                        subnet["state"],
                    )
                    continue
                else:
                    eprint_fmt(
                        "Version %s targeting subnet %s in rollout %s is %s, taking into account",
                        subnet["git_revision"],
                        subnet["subnet_id"],
                        rollout["name"],
                        subnet["state"],
                    )
                t = batch.get("end_time") or batch.get("actual_start_time") or batch["planned_start_time"]
                if subnet["subnet_id"] not in subnet_to_revision:
                    subnet_to_revision[subnet["subnet_id"]] = []
                subnet_to_revision[subnet["subnet_id"]].append((t, subnet["git_revision"]))

    # Now we have a list of subnets associated with each
    # Git revision coupled with the putative date or actual
    # finish date for the revision.  Let's fish the latest
    # revision for each subnet, and get that.

    return {
        subnet_id: [revision for unused_date, revision in sorted(datestring_revision_tuple)][-1]
        for subnet_id, datestring_revision_tuple in subnet_to_revision.items()
    }


def fetch_versions_from_public_dashboard():  # type: () -> dict[str, PublicDashboardSubnet]
    """
    Fetch data from public dashboard

    Returns a map of subnet_id -> {replica_version_id, subnet_type} describing
    the version currently running on each mainnet subnet and its type.

    Panics if the parsed data is not in the expected format.
    Returns an empty dict if the action is retriable.
    """
    url = PUBLIC_DASHBOARD_ENDPOINT
    try:
        data = cast(PDSubnetsResponse, request_json(url))
    except Exception as e:
        eprint(f"Error fetching / decoding data from {url}: {e}.  Returning no versions.")
        return dict()

    subnets = data["subnets"]
    subnet_versions = {}  # type: dict[str, PublicDashboardSubnet]
    for subnet in subnets:
        try:
            latest_replica_version = list(
                sorted(
                    [r for r in subnet["replica_versions"] if r.get("executed_timestamp_seconds")],
                    key=lambda rr: rr.get("executed_timestamp_seconds") or 0,  # the or 0 to satisfy py3.8 typechecking
                )
            )[-1]
            subnet_versions[subnet["subnet_id"]] = {
                "replica_version_id": latest_replica_version["replica_version_id"],
                "subnet_type": subnet["subnet_type"],
            }
        except IndexError:
            raise RuntimeWarning("Subnet %s does not have any executed version proposals" % subnet["subnet_id"])

    return subnet_versions


def main():
    # The public dashboard is the source of truth for which subnets exist on
    # mainnet and their types.
    # The rollout dashboard tells us which version each subnet is being upgraded to.
    public_subnets = fetch_versions_from_public_dashboard()
    rollout_versions = fetch_versions_from_rollout_dashboard()

    eprint(f"Public dashboard subnets: {json.dumps(public_subnets)}")
    eprint(f"Rollout dashboard versions: {json.dumps(rollout_versions)}")

    if not public_subnets:
        # At this moment if we don't have any starting version we cannot proceed
        raise RuntimeError(f"Didn't find any subnets from: {PUBLIC_DASHBOARD_ENDPOINT}")

    # When there is no active rollout the rollout dashboard is empty; in that
    # case we simply qualify from whatever the public dashboard reports for each
    # subnet (including cloud engines, which follow the NNS subnet).
    have_rollout = bool(rollout_versions)

    # The version cloud engine subnets should be qualified from: they follow the
    # NNS subnet's GuestOS version for now.  Prefer the in-progress rollout version, and
    # fall back to whatever the NNS subnet is currently running on mainnet.
    nns_version = rollout_versions.get(NNS_SUBNET_ID)
    if nns_version is None and NNS_SUBNET_ID in public_subnets:
        nns_version = public_subnets[NNS_SUBNET_ID]["replica_version_id"]

    versions = set()  # type: set[str]
    for subnet_id, subnet in public_subnets.items():
        if subnet["subnet_type"] == CLOUD_ENGINE_SUBNET_TYPE:
            # Cloud engines run the NNS version.
            if nns_version is None:
                raise RuntimeError(
                    "Cloud engine subnet %s requires the NNS version, but neither the rollout "
                    "dashboard nor the public dashboard has an entry for the NNS subnet %s" % (subnet_id, NNS_SUBNET_ID)
                )
            versions.add(nns_version)
        elif not have_rollout:
            # No active rollout: qualify from the version the subnet currently
            # runs on mainnet, per the public dashboard.
            versions.add(subnet["replica_version_id"])
        elif subnet_id in rollout_versions:
            # A non-cloud-engine subnet during an active rollout: qualify from
            # the version the rollout dashboard reports for it.
            versions.add(rollout_versions[subnet_id])
        else:
            # An active rollout should target every non-cloud-engine subnet, so
            # a missing entry means something is wrong.
            raise RuntimeError("Non-cloud-engine subnet %s has no entry in the rollout dashboard data" % subnet_id)

    unique_versions = sorted(versions)
    if not unique_versions:
        raise RuntimeError(
            f"Didn't find any versions from:\n\t1. {ROLLOUT_DASHBOARD_ENDPOINT}\n\t2. {PUBLIC_DASHBOARD_ENDPOINT}"
        )
    eprint(f"Will qualify, starting from versions: {json.dumps(unique_versions)}")
    matrix = {"version": unique_versions}
    print(json.dumps(matrix))


if __name__ == "__main__":
    main()
