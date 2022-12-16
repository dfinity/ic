# This test II integration and the use of delegates to sign requests to
# the counter canister.
#
# This code is under development. It will be converted to a real scalability
# suite experiment soon, but already can serve as a baseline for others
# to explore performance related to the use of BLS signatures and delegations.
import asyncio
import dataclasses
import functools
import logging
import multiprocessing
import os
import random
import re
import statistics
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass

import gflags
import matplotlib.pyplot as plt
from ic.agent import Agent
from ic.agent import sign_request
from ic.canister import Canister
from ic.client import Client
from ic.principal import Principal
from termcolor import colored

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from common import misc  # noqa
from common.delegation import get_delegation  # noqa

FLAGS = gflags.FLAGS

gflags.DEFINE_string("targets", None, "Version of the guest OS to boot")
gflags.MarkFlagAsRequired("targets")
gflags.DEFINE_integer("num_procs", 16, "Number of Python processes to use")
gflags.DEFINE_integer("num_tasks", 10, "Number of asyncio tasks per process")
gflags.DEFINE_integer("num_requests", 5, "Number of requests per task")
gflags.DEFINE_float("total_request_rate", 30.0, "Number of requests per second")

# Offset in miliseconds before issuing the first call
# If the offset is too small, the first few calls will be sent in a burst
START_OFFSET_MS = 500


if "CI_PIPELINE_ID" in os.environ:
    print("Not running this test on the pipeline just yet.")
    sys.exit(0)


def install_counter_canister():
    """
    Poor man's counter canister install.

    Will go away when properly using the suite.
    """
    cid = None
    misc.load_artifacts("../artifacts/release")
    workload_generator_path = "../artifacts/release/ic-workload-generator"
    cmd = [workload_generator_path, host_url, "-n", "1", "-r", "0"]
    p = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
    )
    wg_output = p.stdout.decode("utf-8").strip()
    for line in wg_output.split("\n"):
        canister_id = re.findall(r"Successfully created canister at URL [^ ]*. ID: [^ ]*", line)
        if len(canister_id):
            cid = canister_id[0].split()[7]

    if cid is None:
        raise Exception("Failed to install counter canister")
    return cid


def parse_counter_return(r: bytes):
    """Counter returns value with least significant byte first."""
    return int.from_bytes(r, "little")


def plot_request_distribution(request_start_times_sec: [float]):
    """
    Plot the time at which requests are triggered to verify equal distribution of requests over time.

    If everything works correctly, this should result in a steady line w/o any steps in it.
    """
    sorted_start_times = sorted(request_start_times_sec)
    start_time = sorted_start_times[0]
    time_since_start = [(s - start_time) for s in sorted_start_times[1:]]

    fig, ax = plt.subplots()
    ax.plot(time_since_start)

    ax.set_xlabel("request number")
    ax.set_ylabel("time since start [s]")
    ax.set_title("Call start times of delegate requests")
    ax.legend()

    plt.xticks(rotation=70)
    plt.subplots_adjust(hspace=0, bottom=0.3)

    outname = "{}.png".format("delegate_calls")
    print("Output of image to: ", outname)

    plt.savefig(outname, dpi=600)


@dataclass
class RequestResult:
    """Represents the result of a potentially async call."""

    num_fails: int
    num_succ: int
    call_time: [float]  # The time from t_start when the request was issued.
    req_ids: [bytes]
    durations: [float]  # Duration to


def reduce_call_return(a: RequestResult, b: RequestResult):
    return RequestResult(
        a.num_fails + b.num_fails,
        a.num_succ + b.num_succ,
        a.call_time + b.call_time,
        a.req_ids + b.req_ids,
        a.durations + b.durations,
    )


async def initiate_update_calls(t_start, rate):
    """
    Triggers NUM_REQUESTS requests at the given rate without polling for the result.

    There is typically one call to this function per asyncio task.
    """
    assert rate < 1000, "Cannot produce requests at a higher frequency than every ms right now"
    ms_between_calls = 1000.0 / rate
    num_failed = 0
    num_succ = 0
    req_ids = []
    call_times = []
    for i in range(FLAGS.num_requests):
        try:
            req = {
                "request_type": "call",
                "sender": delegated_agent.identity.sender().bytes,
                "canister_id": Principal.from_str(cid).bytes if isinstance(cid, str) else cid.bytes,
                "method_name": "write",
                "arg": [],
                "nonce": uuid.uuid4().bytes,
                "ingress_expiry": delegated_agent.get_expiry_date(),
            }
            req_id, data = sign_request(req, delegated_agent.identity)
            # Sleep until it's time to issue the request while yielding to other tasks
            # We add an offset here to avoid the first few messages being sent in batches (if e.g. a lot of time has
            # already been passed when this code is first running).
            # We also add a per-task random time 0..ms_between_calls to avoid steps in the distribution, where
            # each task sends a request exactly at the same time and then waits exactly the same amount.
            offset_ms = START_OFFSET_MS + random.randint(0, int(ms_between_calls))
            while (time.time() - t_start) * 1000 < offset_ms + (i * ms_between_calls):
                await asyncio.sleep(0)  # sleep(0) = yield: https://docs.python.org/3/library/asyncio-task.html#sleeping
            call_times.append(time.time() - t_start)
            await delegated_agent.client.call_async(cid, req_id, data, timeout=1)
            num_succ += 1
            req_ids.append(req_id)
        except Exception:
            logging.debug(logging.traceback.format_exc())
            num_failed += 1
    return RequestResult(num_failed, num_succ, call_times, req_ids, [])


async def poll_existing_requests(req_ids):
    """
    Poll the given request IDs asynchronously.

    There is normally one such call for each asyncio task.
    """
    logging.debug("Waiting for requests: ", len(req_ids))
    t_end = int(time.time() + 60 * 3)
    for req_id in req_ids:
        try:
            req_timeout = max(t_end - int(time.time()), 1)
            status, result = await delegated_agent.poll_async(cid, req_id, timeout=req_timeout)
            logging.debug(status, result)
        except Exception:
            logging.debug(logging.traceback.format_exc())


async def run_all(arg):
    """
    Issues update calls at the given rate.

    Update calls are first all triggered by sending submitting ingress messages.
    Only after all ingress messages have been triggered are we starting to
    poll the ingress history for each request to learn whether or not the request was successful.

    Note that if too many requests are issued, the request ID might not be available on read_state
    any longer.

    Also not that this function is unsuitable for measuring request latencies, as no polling will
    be executed for any requests until all requests have been submitted. The workload generator
    is a better fit for such cases.

    t_start indicates a common start time to be used to calculate duration and other statistics.
    """
    t_start, rate = arg
    calls = [initiate_update_calls(t_start, rate / FLAGS.num_tasks) for _ in range(FLAGS.num_tasks)]
    raw_results = await asyncio.gather(*calls)
    # The first request is only issued after START_OFFSET_MS miliseconds
    first_request_start_secs = t_start + (START_OFFSET_MS / 1000.0)
    duration = time.time() - first_request_start_secs
    req_ids_per_task = [e.req_ids for e in raw_results]
    calls = [poll_existing_requests(req_ids) for req_ids in req_ids_per_task]
    await asyncio.gather(*calls)
    result = functools.reduce(reduce_call_return, raw_results)
    return dataclasses.replace(result, durations=[duration])


def run_proc(t_start):
    result = asyncio.run(run_all(t_start))
    return result


misc.parse_command_line_args()
host_url = f"http://[{FLAGS.targets}]:8080"

print(colored("WARNING: update calls should be run round-robin against all nodes in the subnet", "red"))

delegated_identity, ii_canister_id, identity_canister_did = get_delegation(host_url)
delegated_client = Client(url=host_url)
delegated_agent = Agent(delegated_identity, delegated_client)
delegatedIdentityCanister = Canister(agent=delegated_agent, canister_id=ii_canister_id, candid=identity_canister_did)

print("QUERY counter canister")

cid = install_counter_canister()

print("query")
print("Counter value before benchmark: ", parse_counter_return(delegated_agent.query_raw(cid, "read", [])))

t_start = time.time()
with multiprocessing.Pool(FLAGS.num_procs) as pool:
    raw_result = pool.map(run_proc, [(t_start, FLAGS.total_request_rate / FLAGS.num_procs)] * FLAGS.num_procs)
    merged = functools.reduce(reduce_call_return, raw_result)
    succ = merged.num_succ
    fail = merged.num_fails
    durations = merged.durations
    print(f"Result in outer layer: successful {succ}, failed {fail}, failure rate: {float(fail)/(fail+succ)}")
    print(f" - durations: mean: {statistics.mean(durations)} stddev: {statistics.stdev(durations)}")
    duration = max(durations)

total_num_requests = FLAGS.num_procs * FLAGS.num_tasks * FLAGS.num_requests
print("Updates: {} - time: {} - per second: {}".format(total_num_requests, duration, total_num_requests / duration))

print("replicated query")
# We execute this one as an update, so that we are sure to get the most recent value
result = parse_counter_return(delegated_agent.update_raw(cid, "read", []))
print("Number in counter canister after benchmark", result)
if result != succ:
    print(colored(f"Number of successful calls {succ} does not match counter value {result}", "red"))

plot_request_distribution(merged.call_time)
