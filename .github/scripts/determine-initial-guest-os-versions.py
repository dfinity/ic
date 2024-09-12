import json
import sys
from enum import StrEnum

import requests
from requests.adapters import HTTPAdapter, Retry
from typing_extensions import Any, Dict, List, Tuple, TypedDict, cast

ROLLOUT_DASHBOARD_ENDPOINT='https://rollout-dashboard.ch1-rel1.dfinity.network/api/v1/rollouts'
PUBLIC_DASHBOARD_ENDPOINT='https://ic-api.internetcomputer.org/api/v3/subnets?format=json'

# Key definitions
EXECUTED_TIMESTAMP_SECONDS = 'executed_timestamp_seconds'
REPLICA_VERSIONS = 'replica_versions'
REPLICA_VERSION_ID = 'replica_version_id'
SUBNETS = 'subnets'

# Minimal subset of API structure needed for rollout dashboard.
# Always keep me in sync with https://github.com/dfinity/dre-airflow/blob/main/rollout-dashboard/server/src/types.rs
# We do not expect to change the API in ways that break code.
class SubnetRolloutState(StrEnum):
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
    actual_start_time: str | None
    end_time: str | None

class RolloutState(StrEnum):
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

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def eprint_fmt(str, *args):
    return # remove me to get some real action
    print((str % args) if args else str, file=sys.stderr)

def session_retry():
    s = requests.Session()
    retries = Retry(
        total=7,
        backoff_factor=0.1,
        status_forcelist=[500, 502, 503, 504],
    )
    s.mount('http://', HTTPAdapter(max_retries=retries))
    return s

def fetch_versions_from_rollout_dashboard() -> list[str] | None:
    """
    Fetch data from rollout dashboard

    Panics if the parsed data is not in the expected format.
    Returns an empty list if the action is retriable.
    """
    url = ROLLOUT_DASHBOARD_ENDPOINT
    try:
        r = session_retry().get(url, timeout=15)
        r.raise_for_status()
        rollouts = cast(List[Rollout], r.json())
    except Exception as e:
        eprint(f"Error fetching / decoding data from {url}: {e}.  Returning no versions.")
        return []

    # The value of the dict entry is datestring, git revision.
    subnet_to_revision: Dict[str, List[Tuple[str, str]]] = {}

    for rollout in reversed(rollouts):  # Oldest to newest
        for batch_num_ignored, batch in rollout["batches"].items():
            for subnet in batch["subnets"]:
                if subnet["state"] in (SubnetRolloutState.error, SubnetRolloutState.predecessor_failed):
                    # This subnet failed?  We ignore it, because it could not have been upgraded.
                    eprint_fmt(
                        "Version %s targeting subnet %s in rollout %s is %s, disregarding",
                        subnet["git_revision"],
                        subnet["subnet_id"],
                        rollout["name"],
                        subnet["state"]
                    )
                    continue
                else:
                    eprint_fmt(
                        "Version %s targeting subnet %s in rollout %s is %s, taking into account",
                        subnet["git_revision"],
                        subnet["subnet_id"],
                        rollout["name"],
                        subnet["state"]
                    )
                t = batch.get("end_time") or batch.get("actual_start_time") or batch["planned_start_time"]
                if subnet["subnet_id"] not in subnet_to_revision:
                    subnet_to_revision[subnet["subnet_id"]] = []
                subnet_to_revision[subnet["subnet_id"]].append((t, subnet["git_revision"]))

    # Now we have a list of subnets associated with each
    # Git revision coupled with the putative date or actual
    # finish date for the revision.  Let's fish the latest
    # revision for each subnet, and get that.
    return list(set([
        list(sorted(datestring_revision_tuple))[-1][1]
        for datestring_revision_tuple in subnet_to_revision.values()
    ]))

def maybe_executed_timestamp(x : Any) -> int:
    if x.get(EXECUTED_TIMESTAMP_SECONDS, None) is None:
        raise Exception(f"Expected '{EXECUTED_TIMESTAMP_SECONDS}' in 'replica_version'")
    return int(x.get(EXECUTED_TIMESTAMP_SECONDS))

def fetch_versions_from_public_dashboard() -> list[str] | None:
    """
    Fetch data from public dashboard

    Panics if the parsed data is not in the expected format.
    Returns an empty list if the action is retriable.
    """
    url = PUBLIC_DASHBOARD_ENDPOINT
    try:
        r = session_retry().get(url, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        eprint(f"Error fetching / decoding data from {url}: {e}.  Returning no versions.")
        return []

    versions = set()
    # Manuel: I'm not modifying this because I do not know the shape
    # of this data structure.
    try:
        if data.get(SUBNETS, None) is None:
            raise Exception(f"Expected '{SUBNETS}' in response")
        subnets = data.get(SUBNETS)
        for subnet in subnets:
            if subnet.get(REPLICA_VERSIONS, None) is None:
                raise Exception(f"Expected '{REPLICA_VERSIONS}' in 'subnet'")
            replica_versions = subnet.get(REPLICA_VERSIONS)
            replica_version = sorted(replica_versions, key=maybe_executed_timestamp, reverse=True)[0]
            if replica_version.get(REPLICA_VERSION_ID, None) is None:
                raise Exception(f"Expected '{REPLICA_VERSION_ID}' in 'replica_version'")
            versions.add(replica_version.get(REPLICA_VERSION_ID))
    except Exception as e:
        # Public dashboard returned json but the format changed. Likely an
        # API change that is not retriable and requires investigation.
        eprint(f"Error while parsing response from {PUBLIC_DASHBOARD_ENDPOINT}: {e}")
        eprint(f"JSON response received:\n{data}")
        exit(1)
    return list(versions)

def main():
    unique_versions = fetch_versions_from_rollout_dashboard()
    if not unique_versions:
        eprint("No active rollouts found, will use versions from public dashboard")
        unique_versions = fetch_versions_from_public_dashboard()

    if not unique_versions:
        # At this moment if we don't have any starting version we cannot proceed
        raise RuntimeError(f"Didn't find any versions from:\n\t1. {ROLLOUT_DASHBOARD_ENDPOINT}\n\t2. {PUBLIC_DASHBOARD_ENDPOINT}")
    eprint(f"Will qualify, starting from versions: {json.dumps(unique_versions)}")
    matrix = {
        "versions": unique_versions
    }
    print(json.dumps(matrix))

if __name__ == "__main__":
    main()
