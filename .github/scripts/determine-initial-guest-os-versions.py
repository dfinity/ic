import json
import sys
from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict, cast
from urllib.request import urlopen

ROLLOUT_DASHBOARD_ENDPOINT = "https://rollout-dashboard.ch1-rel1.dfinity.network/api/v1/rollouts"
PUBLIC_DASHBOARD_ENDPOINT = "https://ic-api.internetcomputer.org/api/v3/subnets?format=json"

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


class PDSubnetsResponse(TypedDict):
    subnets: List[PDSubnet]


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def eprint_fmt(str, *args):
    return  # remove me to get some real action
    print((str % args) if args else str, file=sys.stderr)


def request_json(url: str) -> Any:
    resp = urlopen(url, timeout=15)
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


def fetch_versions_from_rollout_dashboard():  # type: () -> list[str] | None
    """
    Fetch data from rollout dashboard

    Panics if the parsed data is not in the expected format.
    Returns an empty list if the action is retriable.
    """
    url = ROLLOUT_DASHBOARD_ENDPOINT
    try:
        rollouts = cast(List[Rollout], request_json(url))
    except Exception as e:
        eprint(f"Error fetching / decoding data from {url}: {e}.  Returning no versions.")
        return []

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
    return list(
        set(
            [
                [revision for unused_date, revision in sorted(datestring_revision_tuple)][-1]
                for datestring_revision_tuple in subnet_to_revision.values()
            ]
        )
    )


def fetch_versions_from_public_dashboard():  # type: () -> list[str] | None
    """
    Fetch data from public dashboard

    Panics if the parsed data is not in the expected format.
    Returns an empty list if the action is retriable.
    """
    url = PUBLIC_DASHBOARD_ENDPOINT
    try:
        data = cast(PDSubnetsResponse, request_json(url))
    except Exception as e:
        eprint(f"Error fetching / decoding data from {url}: {e}.  Returning no versions.")
        return []

    subnets = data["subnets"]
    versions = set()
    for subnet in subnets:
        try:
            latest_replica_version = list(
                sorted(
                    [r for r in subnet["replica_versions"] if r.get("executed_timestamp_seconds")],
                    key=lambda rr: rr.get("executed_timestamp_seconds") or 0,  # the or 0 to satisfy py3.8 typechecking
                )
            )[-1]
            versions.add(latest_replica_version["replica_version_id"])
        except IndexError:
            raise RuntimeWarning("Subnet %s does not have any executed version proposals" % subnet["subnet_id"])

    return list(versions)


def main():
    unique_versions = fetch_versions_from_rollout_dashboard()
    if not unique_versions:
        eprint("No active rollouts found, will use versions from public dashboard")
        unique_versions = fetch_versions_from_public_dashboard()

    if not unique_versions:
        # At this moment if we don't have any starting version we cannot proceed
        raise RuntimeError(
            f"Didn't find any versions from:\n\t1. {ROLLOUT_DASHBOARD_ENDPOINT}\n\t2. {PUBLIC_DASHBOARD_ENDPOINT}"
        )
    eprint(f"Will qualify, starting from versions: {json.dumps(unique_versions)}")
    matrix = {"version": unique_versions}
    print(json.dumps(matrix))


if __name__ == "__main__":
    main()
