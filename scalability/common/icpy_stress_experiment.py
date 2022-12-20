import asyncio
import dataclasses
import functools
import logging
import multiprocessing
import random
import time
import uuid
from dataclasses import dataclass

import gflags
import matplotlib.pyplot as plt
from common.base_experiment import BaseExperiment
from common.delegation import get_delegation  # noqa
from ic.agent import Agent
from ic.agent import sign_request
from ic.client import Client
from ic.identity import Identity
from ic.principal import Principal
from termcolor import colored

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("num_procs", 16, "Number of Python processes to use")
gflags.DEFINE_integer("num_tasks", 10, "Number of asyncio tasks per process")
gflags.DEFINE_integer("num_requests", 5, "Number of requests per task")

# Offset in miliseconds before issuing the first call
# If the offset is too small, the first few calls will be sent in a burst
START_OFFSET_MS = 500


@dataclass
class RequestResult:
    """Represents the result of a potentially async call."""

    num_fail_submit: int
    num_succ_submit: int
    call_time: [float]  # The time from t_start when the request was issued
    req_ids: [bytes]
    durations: [float]  # Duration to
    status_codes: {str: int}  # Status code of successfully submitted requests


@dataclass
class StressConfiguration:
    """Configuration of the stress to apply to the system."""

    t_start: float
    rate: float
    agents: [Agent]
    canister_id: str


def reduce_request_result(a: RequestResult, b: RequestResult):
    return RequestResult(
        a.num_fail_submit + b.num_fail_submit,
        a.num_succ_submit + b.num_succ_submit,
        a.call_time + b.call_time,
        a.req_ids + b.req_ids,
        a.durations + b.durations,
        {
            k: a.status_codes.get(k, 0) + b.status_codes.get(k, 1)
            for k in set(list(a.status_codes.keys()) + list(b.status_codes.keys()))
        },
    )


async def initiate_update_calls(config: StressConfiguration):
    """
    Triggers NUM_REQUESTS requests at the given rate without polling for the result.

    There is typically one call to this function per asyncio task.
    """
    assert config.rate < 1000, "Cannot produce requests at a higher frequency than every ms right now"
    ms_between_calls = 1000.0 / config.rate
    num_failed = 0
    num_succ_submit = 0
    req_ids = []
    call_times = []
    for i in range(FLAGS.num_requests):
        try:
            this_agent = config.agents[i % len(config.agents)]
            cid = config.canister_id
            req = {
                "request_type": "call",
                "sender": this_agent.identity.sender().bytes,
                "canister_id": Principal.from_str(cid).bytes if isinstance(cid, str) else cid.bytes,
                "method_name": "write",
                "arg": [],
                "nonce": uuid.uuid4().bytes,
                "ingress_expiry": this_agent.get_expiry_date(),
            }
            req_id, data = sign_request(req, this_agent.identity)
            # Sleep until it's time to issue the request while yielding to other tasks
            # We add an offset here to avoid the first few messages being sent in batches (if e.g. a lot of time has
            # already been passed when this code is first running).
            # We also add a per-task random time 0..ms_between_calls to avoid steps in the distribution, where
            # each task sends a request exactly at the same time and then waits exactly the same amount.
            offset_ms = START_OFFSET_MS + random.randint(0, int(ms_between_calls))
            while (time.time() - config.t_start) * 1000 < offset_ms + (i * ms_between_calls):
                # sleep(0) is basically a yield: https://docs.python.org/3/library/asyncio-task.html#sleeping
                await asyncio.sleep(0)
            call_times.append(time.time() - config.t_start)
            await this_agent.client.call_async(cid, req_id, data, timeout=1)
            num_succ_submit += 1
            req_ids.append(req_id)
        except Exception:
            logging.debug(logging.traceback.format_exc())
            num_failed += 1
    return RequestResult(num_failed, num_succ_submit, call_times, req_ids, [], {})


async def poll_existing_requests(config, req_ids):
    """
    Poll the given request IDs asynchronously.

    There is normally one such call for each asyncio task.
    """
    logging.debug("Waiting for requests: ", len(req_ids))
    t_end = int(time.time() + 60 * 3)
    cid = config.canister_id
    status_histogram = {}
    for i, req_id in enumerate(req_ids):
        try:
            # Entries in req_id are processed here in the same order they have been
            # added in initiate_update_calls, so we can use the same index to find the agent.
            # Even if it wasn't the same agent, it shouldn't matter since the ingress
            # history should be the same on all nodes.
            this_agent = config.agents[i % len(config.agents)]
            req_timeout = max(t_end - int(time.time()), 1)
            status, result = await this_agent.poll_async(cid, req_id, timeout=req_timeout)
            status_histogram[status] = status_histogram.get(status, 0) + 1
            logging.debug(status, result)
        except Exception:
            logging.debug(logging.traceback.format_exc())
    return status_histogram


async def run_all_async(config):
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
    per_task_config = dataclasses.replace(config, rate=config.rate / FLAGS.num_tasks)
    calls = [initiate_update_calls(per_task_config) for _ in range(FLAGS.num_tasks)]
    raw_results = await asyncio.gather(*calls)
    # The first request is only issued after START_OFFSET_MS miliseconds
    first_request_start_secs = config.t_start + (START_OFFSET_MS / 1000.0)
    duration = time.time() - first_request_start_secs
    req_ids_per_task = [e.req_ids for e in raw_results]
    calls = [poll_existing_requests(config, req_ids) for req_ids in req_ids_per_task]
    status_histogram = await asyncio.gather(*calls)
    assert len(status_histogram) == len(raw_results)
    raw_results = [dataclasses.replace(r, status_codes=s) for (r, s) in zip(raw_results, status_histogram)]
    result = functools.reduce(reduce_request_result, raw_results)
    return dataclasses.replace(result, durations=[duration])


def run_proc(config: StressConfiguration):
    return asyncio.run(run_all_async(config))


def plot_request_distribution(request_start_times_sec: [float], outname: str):
    """
    Plot the time at which requests are triggered to verify equal distribution of requests over time.

    If everything works correctly, this should result in a steady line w/o any steps in it.
    """
    sorted_start_times = sorted(request_start_times_sec)
    start_time = sorted_start_times[0]
    time_since_start = [(s - start_time) for s in sorted_start_times[1:]]

    fig, ax = plt.subplots()
    ax.plot(time_since_start, label="request triggered at time")

    ax.set_xlabel("request number")
    ax.set_ylabel("time since start [s]")
    ax.set_title("Call start times of delegate requests")
    ax.legend()

    plt.xticks(rotation=70)
    plt.subplots_adjust(hspace=0, bottom=0.3)

    print("Request start times plotted to: ", outname, colored(" <- this should be close to a straight line", "blue"))

    plt.savefig(outname, dpi=600)


class IcPyStressExperiment(BaseExperiment):
    """
    A type of experiment that uses ic-py as a workload generator.

    While this is less suitable to generate high loads yet and experiments based on this type
    cannot currently accurately measure request latency, it allows for faster prototyping and
    supports delegations.
    """

    def __init__(self, use_delegation: bool = True):
        """Init."""
        super().__init__(request_type="update")
        self.host_ip = self.get_machine_to_instrument()
        self.host_url = f"http://[{self.host_ip}]:8080"
        if use_delegation:
            delegated_identity, _, _ = get_delegation(self.host_url)
            self.identity = delegated_identity
        else:
            self.identity = Identity()

    def get_agent_for_ip(self, u):
        return Agent(self.identity, Client(url=f"http://[{u}]:8080"))

    def run_all(self, rps: float, target_ipaddresses: [str], canister_id: str):
        print(f"Running with load {rps} on targets {target_ipaddresses}")

        assert len(target_ipaddresses) > 0
        agents = [self.get_agent_for_ip(u) for u in target_ipaddresses]
        config = StressConfiguration(time.time(), rps / FLAGS.num_procs, agents, canister_id)

        with multiprocessing.Pool(FLAGS.num_procs) as pool:
            raw_result = pool.map(run_proc, [config] * FLAGS.num_procs)
            return functools.reduce(reduce_request_result, raw_result)
