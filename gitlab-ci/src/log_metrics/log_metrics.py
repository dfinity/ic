#!/usr/bin/env python3
"""
Send data about a CI job that has run to ElasticSearch.

We get our data from three places:

1. Environment variables that Gitlab CI sets.
2. Data passed to its command-line, as "key=value" pairs.
3. JSON objects written to a file with a JSON extension. To have your data uploaded,
   you can write your object to a file called `<your key>.json` and place that file
   in the <repo_root>/data_to_upload/ directory. The script will pick
   it up and send the data to ElasticSearch, under `your key` in the main ES object.
"""
import datetime
import http.client
import json
import os
import random
import sys
import time
import traceback
import urllib.request
from pathlib import Path
from pprint import pprint
from typing import Any
from typing import Dict

from notify_slack import send_message


ES_NODES = ["elasticsearch-node-%s.dfinity.systems" % i for i in range(3)]


def get_data_from_files(data_dir: str, default_index: str) -> Dict[str, Dict[str, Any]]:
    """
    Load  data from files.

    If a loaded JSON object contains a key called `__index`, the value of that key is
    used as the index name, and all the data is included directly as-is into the ES document.

    If the index name does not exist, the data is added to `default_index`, under a key
    with the same name as the file minus the `.json` extension.
    """
    outdir = Path(data_dir)
    if not outdir.is_dir():
        print("The additional data directory does not exist, skipping...")
        return {}

    json_files = [x for x in outdir.iterdir() if x.is_file() and x.name.lower().endswith(".json")]

    data = {default_index: {}}
    for json_file in json_files:
        with json_file.open() as j:
            try:
                # Name the key the same as the filename without the extension.
                file_data = json.load(j)

                # Just to be on the safe side, if someone tries to send non-dict data
                if not isinstance(file_data, dict):
                    file_data = {"data": file_data}
            except Exception as e:
                print(f"Could not load contents of {json_file.name}, skipping. Reason:\n%s" % e)

            if "__index" in file_data:
                # We have an index name.
                index_name = file_data["__index"]
                del file_data["__index"]
                data[index_name] = file_data
            else:
                # No index name, use the default.
                data[default_index][json_file.name[:-5]] = file_data

    return data


def get_env_data() -> Dict[str, str]:
    """Get relevant metrics data from the environment."""
    data = {}
    for varname in [
        "CI",
        "CI_COMMIT_BEFORE_SHA",
        "CI_COMMIT_BRANCH",
        "CI_COMMIT_REF_NAME",
        "CI_COMMIT_REF_PROTECTED",
        "CI_COMMIT_SHA",
        "CI_COMMIT_TAG",
        "CI_COMMIT_TIMESTAMP",
        "CI_CONCURRENT_ID",
        "CI_CONCURRENT_PROJECT_ID",
        "CI_ENVIRONMENT_NAME",
        "CI_ENVIRONMENT_SLUG",
        "CI_EXTERNAL_PULL_REQUEST_IID",
        "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
        "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA",
        "CI_JOB_ID",
        "CI_JOB_IMAGE",
        "CI_JOB_MANUAL",
        "CI_JOB_NAME",
        "CI_JOB_STAGE",
        "CI_JOB_STATUS",
        "CI_MERGE_REQUEST_ID",
        "CI_NODE_INDEX",
        "CI_NODE_TOTAL",
        "CI_PIPELINE_ID",
        "CI_PIPELINE_SOURCE",
        "CI_RUNNER_ID",
        "GITLAB_USER_ID",
        "GITLAB_USER_LOGIN",
        "DISKIMG_BRANCH",
    ]:
        if os.environ.get(varname):
            data[varname] = os.environ[varname]
    return data


def post_data(index_name: str, data: Dict[str, str]) -> http.client:
    """Post `data` to our ElasticSearch instance at `index_name`."""
    # Shuffle the list so our attempts are in random order, instead of hammering
    # hosts in order.
    random.shuffle(ES_NODES)

    exc = None
    body = None
    # 5 * 2 seconds = 5 minutes
    for i in range(5):
        node = ES_NODES[i % len(ES_NODES)]
        req = urllib.request.Request(
            f"http://{node}:9200/{index_name}/_doc/",
            data=json.dumps(data).encode(),
            headers={"content-type": "application/json"},
        )

        try:
            response = urllib.request.urlopen(req, timeout=30)
            break
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            exc = e
        except Exception as e:
            exc = e
        print("Request failed, retry in 60 seconds")
        time.sleep(2)
    else:
        job_id = os.environ.get("CI_JOB_ID")
        job_url = os.environ.get("CI_JOB_URL")

        print("Max retries exceeded")
        error_message = (
            "ERROR: log-metrics could not send data to ElasticSearch for "
            f"{job_url}|job {job_id}>. "
            "Exception details:\n```%s```" % "".join(traceback.format_exception(None, exc, exc.__traceback__))
        )
        error_message += f"\n\nResponse body:\n```\n{body}\n```"
        send_message(message=error_message, channel="precious-bots")
        sys.exit(0)
    return response


def main():
    """Program entry main."""
    timestamp = datetime.datetime.now().isoformat()
    args = {"timestamp": timestamp}
    for arg in sys.argv[1:]:
        k, v = arg.split("=", 1)
        k, v = k.strip(), v.strip()
        try:
            # If the argument can be converted to an int, do that.
            v = int(v)
        except ValueError:
            try:
                # If the argument can be converted to a float, do that.
                v = float(v)
            except ValueError:
                pass
        args[k] = v

    default_index_name = "gitlab-ci-metrics-%s" % datetime.date.today().year
    data = {default_index_name: args}
    env_data = get_env_data()
    data[default_index_name].update(env_data)

    data_from_files = get_data_from_files("data_to_upload", default_index=default_index_name)
    for index_name, value in data_from_files.items():
        if index_name in data:
            # This can really only be the default index, but it felt wrong
            # to do `if index_name == default_index_name`.
            data[index_name].update(value)
        else:
            data[index_name] = value

        # We need the env data (and timestamp) to be added to all found indexes
        # so that we can join this data with other jobs
        data[index_name].update(env_data)
        data[index_name]["timestamp"] = timestamp

    errors = False
    for index_name, value in data.items():
        index_name = index_name.replace(":", "-")
        print(f"Posting data to {index_name}:")
        pprint(value, depth=2)
        response = post_data(index_name, value)
        if 200 <= response.status < 300:
            print("Posted successfully.")
        else:
            errors = True
            print(f"There was an error while posting to {index_name}: {response.read()}")

    if errors:
        exit("There were some errors.")


if __name__ == "__main__":
    main()
