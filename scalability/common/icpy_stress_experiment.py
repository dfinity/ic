import asyncio
import dataclasses
import functools
import json
import logging
import math
import multiprocessing
import os
import random
import statistics
import time
import traceback
import uuid
from dataclasses import dataclass

import gflags
import matplotlib.pyplot as plt
from ic.agent import Agent, sign_request
from ic.client import Client
from ic.identity import Identity
from ic.principal import Principal
from termcolor import colored

from common.base_experiment import BaseExperiment
from common.delegation import get_delegation, get_ii_canister_id

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("num_procs", 16, "Number of Python processes to use")
gflags.DEFINE_integer("num_identities", 10, "Number of identities to issue load with")

CALL_TIMEOUT_SEC = 1
POLL_TIMEOUT_SEC = 60

# Offset in miliseconds before issuing the first call
# If the offset is too small, the first few calls will be sent in a burst
START_OFFSET_MS = 500


@dataclass
class RequestResult:
    """Represents the result of a potentially async call."""

    num_fail_submit: int
    num_succ_submit: int
    num_fail_executed: int
    num_succ_executed: int
    call_time: [float]  # The time from t_start when the request was issued. Request i should be at i * rate
    req_ids: [bytes]
    # Latency of requests from submission until Suite                                     detects successful execution
    durations: [float]
    status_codes: {str: int}  # Status code of successfully submitted requests
    exception_histogram: {str: int}


@dataclass
class StressConfiguration:
    """Configuration of the stress to apply to the system."""

    t_start: float
    rate: float
    num_requests: int
    agents: [Agent]
    canister_id: str
    pid: int
    tid: int
    total_duration: int
    method: str
    payload: bytes
    use_updates: bool


def get_default_stress_configuration() -> StressConfiguration:
    return StressConfiguration(
        t_start=0,
        rate=0,
        num_requests=0,
        agents=[],
        canister_id=None,
        pid=-1,
        tid=-1,
        total_duration=0,
        method=None,
        payload=[],
        use_updates=True,
    )


def reduce_request_result(a: RequestResult, b: RequestResult):
    """Reduce two RequestResults to be used in functools.reduce"""
    return RequestResult(
        a.num_fail_submit + b.num_fail_submit,
        a.num_succ_submit + b.num_succ_submit,
        a.num_fail_executed + b.num_fail_executed,
        a.num_succ_executed + b.num_succ_executed,
        a.call_time + b.call_time,
        a.req_ids + b.req_ids,
        a.durations + b.durations,
        {
            k: a.status_codes.get(k, 0) + b.status_codes.get(k, 1)
            for k in set(list(a.status_codes.keys()) + list(b.status_codes.keys()))
        },
        {
            k: a.exception_histogram.get(k, 0) + b.exception_histogram.get(k, 1)
            for k in set(list(a.exception_histogram.keys()) + list(b.exception_histogram.keys()))
        },
    )


async def do_query(agent: Agent, config: StressConfiguration, call_idx: int):
    """
    Do a single query call.

    call_idx is the request number. Request number i is triggered at second: i * 1/rps.
    """
    canister_id = config.canister_id
    ms_between_calls = 1000.0 / config.rate

    # Sleep until it's time to issue the query while yielding to other tasks
    # We add an offset here to avoid the first few messages being sent in batches (if e.g. a lot of time has
    # already been passed when this code is first running).
    # We also add a per-task random time 0..ms_between_calls to avoid steps in the distribution, where
    # each task sends a request exactly at the same time and then waits exactly the same amount.
    offset_ms = START_OFFSET_MS + random.randint(0, int(ms_between_calls))
    while (time.time() - config.t_start) * 1000 < offset_ms + (call_idx * ms_between_calls):
        # sleep(0) is basically a yield: https://docs.python.org/3/library/asyncio-task.html#sleeping
        await asyncio.sleep(0)

    request_start_time = time.time()
    result = await agent.query_raw_async(canister_id, config.method, config.payload)

    return request_start_time, result


async def submit(agent: Agent, config: StressConfiguration, call_idx: int):
    """
    Submit a single request.

    call_idx is the request number. Request number i is triggered at second: i * 1/rps.
    """
    canister_id = config.canister_id
    ms_between_calls = 1000.0 / config.rate
    # Twice the total duration, to make sure we have enough time to query the ingress
    # Note that the IC might refuse the ingress message because of this. The spec does not
    # specify which value is allowed as max, only that it may refuse it if it is "too far in the future".
    # ingress_expiry = int(time.time() + 2 * config.total_duration) * 10**9
    req = {
        "request_type": "call",
        "sender": agent.identity.sender().bytes,
        "canister_id": Principal.from_str(canister_id).bytes if isinstance(canister_id, str) else canister_id.bytes,
        "method_name": config.method,
        "arg": config.payload,
        "nonce": uuid.uuid4().bytes,
        "ingress_expiry": agent.get_expiry_date(),
    }
    req_id, data = sign_request(req, agent.identity)
    # Sleep until it's time to issue the request while yielding to other tasks
    # We add an offset here to avoid the first few messages being sent in batches (if e.g. a lot of time has
    # already been passed when this code is first running).
    # We also add a per-task random time 0..ms_between_calls to avoid steps in the distribution, where
    # each task sends a request exactly at the same time and then waits exactly the same amount.
    offset_ms = START_OFFSET_MS + random.randint(0, int(ms_between_calls))
    while (time.time() - config.t_start) * 1000 < offset_ms + (call_idx * ms_between_calls):
        # sleep(0) is basically a yield: https://docs.python.org/3/library/asyncio-task.html#sleeping
        await asyncio.sleep(0)

    request_start_time = time.time()
    await agent.client.call_async(canister_id, req_id, data, timeout=CALL_TIMEOUT_SEC)

    return req_id, request_start_time


def __exception_histogram(e: Exception, histogram: dict, known_exceptions: list, label: str):
    """Parse exceptions and create a histogram by exception name"""
    key = str(type(e).__name__)
    histogram[key] = histogram.get(key, 0) + 1

    if key is None or len(key) < 1:
        print("Could not get a exception key for: ", e)
        logging.warning(logging.traceback.format_exc())
        print(type(e), type(e).__name__)
        return

    if key not in known_exceptions:
        print(f"Add key [{key}] to list of expected exceptions for {label} to silence this exception and just count it")
        traceback.print_exc()


async def poll(agent: Agent, canister_id, req_id: bytes, status_histogram: dict):
    """Poll a previously submitted requests by its ID"""
    # Entries in req_id are processed here in the same order they have been
    # added in initiate_update_calls, so we can use the same index to find the agent.
    # Even if it wasn't the same agent, it shouldn't matter since the ingress
    # history should be the same on all nodes.
    assert req_id is not None
    status = None
    try:
        status, result = await agent.poll_async(canister_id, req_id, timeout=POLL_TIMEOUT_SEC)
        status_histogram[status] = status_histogram.get(status, 0) + 1
        logging.debug(status, result)
    except Exception as e:
        # If polling fails, just keep track of failure and move on.
        key = "poll_" + str(type(e).__name__)
        status_histogram[key] = status_histogram.get(key, 0) + 1
        logging.debug(f"Failed to poll: {e}")
    return status == "replied"


async def execute_query_call(config: StressConfiguration):
    """Execute query calls for the given configuration."""
    assert not config.use_updates
    request_idx = config.tid
    request_result = RequestResult(0, 0, 0, 0, [], [], [], {}, {})

    try:

        agent = config.agents[random.randint(0, len(config.agents) - 1)]
        # Execute query call - will raise Exception unless successful
        req_start_time, _result = await do_query(agent, config, request_idx)

        # Request was successful
        request_result.call_time.append(req_start_time - config.t_start)
        request_result.durations.append(time.time() - req_start_time)
        request_result.num_succ_submit += 1
        request_result.status_codes["replied"] = request_result.status_codes.get("replied", 0) + 1

    except Exception as e:
        # Submitting failed
        request_result.num_fail_submit += 1
        __exception_histogram(
            e, request_result.exception_histogram, ["ReadTimeout", "ConnectTimeout", "ReadError"], "querying"
        )
        request_result.status_codes["exception"] = request_result.status_codes.get("exception", 0) + 1

    return request_result


async def execute_update_call(config: StressConfiguration):
    """
    Triggers a single requests at a time calculated from config.tid

    There is typically one call to this function per asyncio task.
    """
    assert config.use_updates
    request_idx = config.tid
    request_result = RequestResult(0, 0, 0, 0, [], [], [], {}, {})

    # Submit
    # ----------------------------------------------------------
    req_id = None
    try:

        agent = config.agents[random.randint(0, len(config.agents) - 1)]
        req_id, req_start_time = await submit(agent, config, request_idx)

        # Request was successful
        request_result.call_time.append(req_start_time - config.t_start)
        request_result.num_succ_submit += 1

        await asyncio.sleep(1)

        try:
            # Start polling the ingress history using the same agent
            status_ok = await poll(agent, config.canister_id, req_id, request_result.status_codes)
            if status_ok:
                request_result.num_succ_executed += 1
                request_result.durations.append(time.time() - req_start_time)
            else:
                request_result.num_fail_executed += 1

        except Exception as e:
            # Polling failed
            request_result.num_fail_executed
            __exception_histogram(e, request_result.status_codes, ["ReadError", "RemoteProtocolError"], "submitting")

    except Exception as e:
        # Submitting failed
        request_result.num_fail_submit += 1
        __exception_histogram(
            e, request_result.exception_histogram, ["ReadTimeout", "ConnectTimeout", "ReadError"], "polling"
        )

    return request_result


async def run_all_async(config: StressConfiguration):
    """
    Issues update calls at the given rate.

    Spawns one asyncio task per update call.
    """
    assert config.rate < 1000, "Cannot produce requests at a higher frequency than every ms right now"
    print(f"proc{config.pid:02}: Starting {config.num_requests} calls at rate {config.rate}")

    if config.use_updates:
        calls = [execute_update_call(dataclasses.replace(config, tid=i)) for i in range(config.num_requests)]
    else:
        calls = [execute_query_call(dataclasses.replace(config, tid=i)) for i in range(config.num_requests)]
    raw_results = await asyncio.gather(*calls)

    # Update result data structure
    return functools.reduce(reduce_request_result, raw_results)


def run_proc(config: StressConfiguration):
    return asyncio.run(run_all_async(config))


def plot_request_distribution(
    request_start_times_sec: [float], request_end_times_sec: [float], outname: str, rate: float
):
    """
    Plot the time at which requests are triggered to verify equal distribution of requests over time.

    If everything works correctly, this should result in a steady line w/o any steps in it.
    """

    def plot_absolute_times(times):
        sorted_times = sorted(times)
        start_time = sorted_times[0]
        time_since_start = [(s - start_time) for s in sorted_times[1:]]
        return [(time, num) for (num, time) in enumerate(time_since_start)]

    start_time_plot = plot_absolute_times(request_start_times_sec)
    end_time_plot = plot_absolute_times(request_end_times_sec)

    _, ax = plt.subplots()
    ax.plot([x for x, _ in start_time_plot], [y for _, y in start_time_plot], label="request triggered at time")
    ax.plot([x for x, _ in end_time_plot], [y for _, y in end_time_plot], label="request finished at time")

    rate_plot = [i * rate for i in range(int(math.ceil(max(request_start_times_sec))))]
    ax.plot(rate_plot, label=f"Requested rate: {rate}/s")

    ax.set_xlabel("time [s]")
    ax.set_ylabel("number of requests")
    ax.set_title("Python stresser timings")
    ax.legend()

    plt.xticks(rotation=70)
    plt.subplots_adjust(hspace=0, bottom=0.3)

    print(
        "Request start times plotted to: ",
        outname,
        colored(" <- sanity check this plot to judge request rates", "blue"),
    )

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
        self.nns_host = self._get_nns_url()
        self.host_ip = self.get_machine_to_instrument()
        self.host_url = f"http://[{self.host_ip}]:8080"
        if use_delegation:
            print(f"Running with {FLAGS.num_identities} delegated indentities.")
            ii_canister_id = get_ii_canister_id(self.nns_host)
            with multiprocessing.Pool(FLAGS.num_procs) as pool:
                # We get all delegates from the same host
                raw_result = pool.starmap(get_delegation, [(self.nns_host, ii_canister_id)] * FLAGS.num_identities)
                self.identities = [element[0] for element in raw_result]
        else:
            print(f"Running with {FLAGS.num_identities} different non-delegated identities.")
            self.identities = [Identity() for _ in range(FLAGS.num_identities)]

    def get_agents_for_ip(self, u):
        return [Agent(identity, Client(url=f"http://[{u}]:8080")) for identity in self.identities]

    def run_all(
        self,
        rps: float,
        duration: int,
        target_ipaddresses: [str],
        canister_id: str,
        stress_configuration: StressConfiguration = None,
    ) -> RequestResult:

        num_requests = int(math.ceil(rps * duration))
        print(f"Running with load {rps} on targets {target_ipaddresses} for {duration} seconds")

        assert len(target_ipaddresses) > 0
        agents = []
        for u in target_ipaddresses:
            agents += self.get_agents_for_ip(u)

        if stress_configuration is None:
            config = StressConfiguration(
                t_start=time.time(),
                rate=rps / FLAGS.num_procs,
                num_requests=int(math.ceil(num_requests / FLAGS.num_procs)),
                agents=agents,
                canister_id=canister_id,
                pid=-1,
                tid=-1,
                total_duration=duration,
                method="write",
                payload=[],
                use_updates=True,
            )
        else:
            config = dataclasses.replace(
                stress_configuration,
                t_start=time.time(),
                rate=rps / FLAGS.num_procs,
                num_requests=int(math.ceil(num_requests / FLAGS.num_procs)),
                agents=agents,
                canister_id=canister_id,
                pid=-1,
                tid=-1,
                total_duration=duration,
            )

        t_start = time.time()
        print(f"Running {FLAGS.num_procs} processes - each with {config.num_requests} requests at {config.rate} rps")
        result = None
        with multiprocessing.Pool(FLAGS.num_procs) as pool:
            raw_result = pool.map(run_proc, [dataclasses.replace(config, pid=i) for i in range(FLAGS.num_procs)])
            result = functools.reduce(reduce_request_result, raw_result)
        print(f"Finished load after {time.time()-t_start}s")

        for exception, num in result.exception_histogram.items():
            print(f"[EXCEPTION_HISTOGRAM] {exception:40} - {num}")

        for k, v in result.status_codes.items():
            print("[STATUS_CODE]", k, v)

        num_succ = 0
        num_fail = 0
        for status, number in result.status_codes.items():
            print(f"{str(status):10} - {number:10.0f}")
            if status == "replied":
                num_succ += number
            else:
                num_fail += number
        executed_failure_rate = 100 * num_fail / (num_fail + num_succ)
        print(f"Failure rate: {executed_failure_rate}")

        total_duration = max(result.call_time) - min(result.call_time)
        print("Average request rate: ", total_duration / (result.num_succ_submit + result.num_fail_submit))

        prev = None
        inter_message_time = []
        for t in sorted(result.call_time):
            if prev is not None:
                inter_message_time.append(t - prev)
            prev = t

        print("Inter-message time [s]: ", statistics.median(inter_message_time), statistics.stdev(inter_message_time))
        print("Rate from inter-message time: ", 1 / statistics.median(inter_message_time))

        print(f"Executed failure before: {result.num_succ_executed} {result.num_fail_executed}")
        result = dataclasses.replace(result, num_succ_executed=num_succ)
        result = dataclasses.replace(result, num_fail_executed=num_fail)
        print(f"Executed failure before: {result.num_succ_executed} {result.num_fail_executed}")

        iteration_uuid = str(uuid.uuid4())
        with open(os.path.join(self.iter_outdir, "icpy-stresser-results" + iteration_uuid), "w") as f:
            # Remove request IDs (they are not Json serializable) and write to file
            f.write(json.dumps(dataclasses.replace(result, req_ids=[]).__dict__, indent=4))

        return result
