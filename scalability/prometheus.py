import json
import os
from typing import List

import gflags
import metrics
import requests

FLAGS = gflags.FLAGS
gflags.DEFINE_boolean("no_prometheus", False, "Set true to disable querying Prometheus.")


class Prometheus(metrics.Metric):
    """Abstraction for collecting prometheus metrics."""

    def end_iteration(self, exp):
        """Benchmark iteration is ended."""
        if FLAGS.no_prometheus:
            return
        print("Getting Prometheus metrics .. ")
        r = get_finalization_rate(exp.testnet, [exp.target_nodes[0]], exp.t_iter_start, exp.t_iter_end)
        finalization_rate = extract_value(r)[0]
        r = get_http_request_duration(
            exp.testnet, [exp.target_nodes[0]], exp.t_iter_start, exp.t_iter_end, exp.request_type
        )
        http_request_duration = extract_value(r)

        r = get_http_request_rate(
            exp.testnet, [exp.target_nodes[0]], exp.t_iter_start, exp.t_iter_end, exp.request_type
        )
        http_request_rate = extract_values(r)

        # Dump Prometheus information.
        with open(os.path.join(exp.iter_outdir, "prometheus.json"), "w") as metrics_file:
            metrics_file.write(
                json.dumps(
                    {
                        "finalization_rate": finalization_rate,
                        "http_request_duration": http_request_duration,
                        "http_request_rate": http_request_rate,
                    }
                )
            )


def extract_value(result):
    return [r["value"] for r in result["data"]["result"]]


def extract_values(result):
    return [r["values"] for r in result["data"]["result"]]


def get_http_request_rate_for_timestamp(testnet, load_hosts, timestamp):
    query = 'job_instance_ic_icsubnet_type_requesttype_status:http_request:rate1m{{{}, request_type=~"query"}}'.format(
        get_common(load_hosts, testnet)
    )

    payload = {"time": timestamp, "query": query}

    r = get_prometheus(payload)
    j = json.loads(r.text)

    # Ensure the returned data's timestamp matches
    assert int(j["data"]["result"][0]["value"][0]) == timestamp

    return j


def get_http_request_rate(testnet, load_hosts, t_start, t_end, request_type="query"):
    RESOLUTION = "60s"
    common = get_common(load_hosts, testnet)
    query = (
        f"rate(replica_http_request_duration_seconds_count{{"
        f'{common}, request_type=~"{request_type}"'
        f"}}[{RESOLUTION}])"
    )

    payload = {"start": t_start, "end": t_end, "step": "10s", "query": query}

    r = get_prometheus_range(payload)
    j = json.loads(r.text)

    return j


def get_execution_query_latency(testnet, load_hosts, t_start, t_end):
    RESOLUTION = "60s"
    assert (
        len(load_hosts) == 1
    )  # Otherwise we need to SUM things up, as in https://grafana.dfinity.systems/d/GWlsOrn7z/execution-metrics-2-0?editPanel=89&orgId=1&from=now-5m&to=now&var-ic=benchmarksmall01&var-ic_subnet=nmql4-wbx55-wqzep-orbrv-bfvdn-q7qgm-mwquu-zlmc7-xtgvg-olns7-vqe&var-instance=All&var-node_instance=All&var-heatmap_period=$__auto_interval_heatmap_period&refresh=10s
    q1 = "rate(execution_query_duration_seconds_sum{{{}}}[{}])".format(get_common(load_hosts, testnet), RESOLUTION)
    q2 = "rate(execution_wasm_compile_sum{{{}}}[{}])".format(get_common(load_hosts, testnet), RESOLUTION)
    q3 = "rate(execution_query_duration_seconds_count{{{}}}[{}])".format(get_common(load_hosts, testnet), RESOLUTION)
    query = "clamp_min({}-{}, 0)/{}".format(q1, q2, q3)

    payload = {"start": t_start, "end": t_end, "step": "10s", "query": query}
    print("Prometheus: {}".format(json.dumps(payload, indent=2)))

    r = get_prometheus_range(payload)
    j = json.loads(r.text)

    return j


def get_canister_install_rate(testnet, hosts, timestamp):
    """Return the canister install rate on the given machine at a 30s time interval ending at the given time."""
    assert len(hosts) == 1  # Otherwise, need to aggregate those machines
    common = get_common(hosts, testnet)
    q = f'rate(execution_subnet_message_duration_seconds_count{{{common},method_name="ic00_install_code"}}[60s])'

    payload = {"time": timestamp, "query": q}
    return json.loads(get_prometheus(payload).text)


def get_num_canisters_installed(testnet, hosts, timestamp):
    """Return the number of canisters installed currently on the given machine in the given testnet."""
    assert len(hosts) == 1
    common = get_common(hosts, testnet)

    q = f'replicated_state_registered_canisters{{{common},status="running"}}'
    payload = {"time": timestamp, "query": q}
    return json.loads(get_prometheus(payload).text)


def get_http_request_duration(testnet, hosts: List[str], t_start, t_end, request_type="query"):

    # Dashboard:
    # https://grafana.dfinity.systems/d/rnF_68BGk/http-handler?viewPanel=6&orgId=1&from=now-15m&to=now&var-ic=mercury&var-ic_subnet=All&var-request_type=All&var-group_by=request_type
    assert t_end - t_start > 60

    metric = "replica_http_request_duration_seconds"
    selector = '{}_bucket{{{},type="read",request_type="{}"}}'.format(metric, get_common(hosts, testnet), request_type)

    payload = {
        "start": t_start,
        "end": t_end,
        "step": "60s",
        "query": "histogram_quantile(0.80, sum by (le) (rate({}[60s])))".format(selector),
    }

    r = get_prometheus(payload)
    return json.loads(r.text)


def get_finalization_rate(testnet, hosts, t_start, t_end):

    # Doesn't make sense to query stuff for really short experiments.
    assert t_end - t_start > 30

    metric = "artifact_pool_consensus_height_stat"
    selector = '{}{{{},type="finalization",pool_type="validated",stat="max"}}'.format(
        metric, get_common(hosts, testnet)
    )

    payload = {
        "time": t_end,
        "query": "avg(rate({}[{}s]))".format(selector, t_end - t_start),
    }
    r = get_prometheus(payload)
    print(f"Prometheus response is: {r.text}")
    return json.loads(r.text)


def get_common(hosts, testnet):

    assert isinstance(hosts, list)

    # We need a very strange escaping for hostnames ..
    metricshosts = "|".join(["\\\\[{}\\\\]:9090".format(h) for h in hosts])
    return 'ic="{}",job="replica",instance=~"{}"'.format(testnet, metricshosts)


def get_prometheus(payload):
    """Query prometheus for metrics."""
    headers = {"Accept": "application/json"}

    print("Executing Prometheus query: ", payload)
    r = requests.get("http://prometheus.dfinity.systems:9090/api/v1/query", headers=headers, params=payload)
    return r


def get_prometheus_range(payload):
    """Query prometheus for metrics."""
    headers = {"Accept": "application/json"}

    print("Executing Prometheus query: ", payload)
    r = requests.get("http://prometheus.dfinity.systems:9090/api/v1/query_range", headers=headers, params=payload)
    return r
