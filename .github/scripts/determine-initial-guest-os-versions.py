import json
from typing_extensions import Any
from urllib.request import Request, urlopen
import urllib.error
import sys

ROLLOUT_DASHBOARD_ENDPOINT='https://rollout-dashboard.ch1-rel1.dfinity.network/api/v1/rollouts'
PUBLIC_DASHBOARD_ENDPOINT='https://ic-api.internetcomputer.org/api/v3/subnets?format=json'

# Key definitions
STATE = 'state'
FAILED = 'failed'
COMPLETE = 'complete'
BATCHES = 'batches'
SUBNETS = 'subnets'
GIT_REVISION = 'git_revision'
EXECUTED_TIMESTAMP_SECONDS = 'executed_timestamp_seconds'
REPLICA_VERSIONS = 'replica_versions'
REPLICA_VERSION_ID = 'replica_version_id'

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def maybe_fetch_data(url : str, timeout : float) -> str | None:
    """Try fetch data from `url`.

    Will try to fetch data and return `None` if the resource is unavailable for some.
    If this call fails other resources should be considered.
    """
    try:
        req = Request(url)
        req.add_header('accept', '*/*')
        req.add_header('user-agent', 'dfinity-ci')
        with urlopen(req, timeout=timeout) as response:
            encoding = response.headers.get_content_charset('utf-8')
            body = response.read()
            return body.decode(encoding)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        eprint(f"Error fetching data from {url}: {e}")
        return None

def ensure_json_response(url : str, timeout : float = 10) -> Any | None:
    response = maybe_fetch_data(url, timeout)
    if response is None:
        # Resource was unavailable, if there are
        # other options they should be considered
        # at this point
        return None

    try:
        return json.loads(response)
    except (json.JSONDecodeError) as e:
        # The resource returned some response but it wasn't json.
        # This error should not be retried and should panic because it was
        # likely an API change and requires investigation.
        eprint(f"Received error when decoding the response from {url}: {e}")
        eprint(f"Response was:\n{response}")
        exit(1)

def fetch_versions_from_rollout_dashboard() -> list[str] | None:
    """Fetch data from rollout dashboard

    Panics if the parsed data is not in the expected format.
    Returns an empty list if the action is retriable.
    """
    data = ensure_json_response(ROLLOUT_DASHBOARD_ENDPOINT)
    if data is None:
        # Resource was unavailable
        return []

    versions = set()
    try:
        for rollout in data:
            if rollout.get(STATE, None) is None:
                raise Exception(f"Expected '{STATE}' in 'rollout'")
            if rollout.get(STATE) in [FAILED, COMPLETE]:
                continue
            if rollout.get(BATCHES, None) is None:
                raise Exception(f"Expected '{BATCHES}' in 'rollout'")
            for batch in rollout.get(BATCHES).values():
                if batch.get(SUBNETS, None) is None:
                    raise Exception(f"Expected '{SUBNETS}' in 'batch'")
                for subnet in batch.get(SUBNETS):
                    if subnet.get(GIT_REVISION, None) is None:
                        raise Exception(f"Expected '{GIT_REVISION}' in 'subnet'")
                    versions.add(subnet.get(GIT_REVISION))
    except Exception as e:
        # Rollout dashboard returned json but the format changed. Likely an
        # API change that is not retriable and requires investigation.
        eprint(f"Error while parsing response from {ROLLOUT_DASHBOARD_ENDPOINT}: {e}")
        eprint(f"Json response received:\n{data}")
        exit(1)
    return list(versions)

def maybe_exectued_timestamp(x : Any) -> int:
    if x.get(EXECUTED_TIMESTAMP_SECONDS, None) is None:
        raise Exception(f"Expected '{EXECUTED_TIMESTAMP_SECONDS}' in 'replica_version'")
    return int(x.get(EXECUTED_TIMESTAMP_SECONDS))

def fetch_versions_from_public_dashboard() -> list[str] | None:
    """Fetch data from public dashboard

    Panics if the parsed data is not in the expected format.
    Returns an empty list if the action is retriable.
    """
    data = ensure_json_response(PUBLIC_DASHBOARD_ENDPOINT)
    if data is None:
        # Resource was unavailable
        return []

    versions = set()
    try:
        if data.get(SUBNETS, None) is None:
            raise Exception(f"Expected '{SUBNETS}' in response")
        subnets = data.get(SUBNETS)
        for subnet in subnets:
            if subnet.get(REPLICA_VERSIONS, None) is None:
                raise Exception(f"Expected '{REPLICA_VERSIONS}' in 'subnet'")
            replica_versions = subnet.get(REPLICA_VERSIONS)
            replica_version = sorted(replica_versions, key=maybe_exectued_timestamp, reverse=True)[0]
            if replica_version.get(REPLICA_VERSION_ID, None) is None:
                raise Exception(f"Expected '{REPLICA_VERSION_ID}' in 'replica_version'")
            versions.add(replica_version.get(REPLICA_VERSION_ID))
    except Exception as e:
        # Public dashboard returned json but the format changed. Likely an
        # API change that is not retriable and requires investigation.
        eprint(f"Error while parsing response from {PUBLIC_DASHBOARD_ENDPOINT}: {e}")
        eprint(f"Json response received:\n{data}")
        exit(1)
    return list(versions)

def main():
    unique_versions = fetch_versions_from_rollout_dashboard()
    if not unique_versions:
        eprint("No active rollouts found, will use versions from public dashboard")
        unique_versions = fetch_versions_from_public_dashboard()

    if not unique_versions:
        # At this moment if we don't have any starting version we cannot proceed
        raise Exception(f"Didn't find any versions from:\n\t1. {ROLLOUT_DASHBOARD_ENDPOINT}\n\t2. {PUBLIC_DASHBOARD_ENDPOINT}")
    eprint(f"Will qualify, starting from versions: {json.dumps(unique_versions)}")
    matrix = {
        "versions": unique_versions
    }
    print(json.dumps(matrix))

if __name__ == "__main__":
    main()
