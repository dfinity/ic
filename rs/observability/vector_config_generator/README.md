# Vector Config Generator

## Synopsis

Periodically check the registry on a given IC for the current topology
(subnets, and the nodes assigned to them).

When the topology changes it writes a JSON file in  [Vector configuration
format](https://vector.dev/docs/reference/configuration/) format.

Vector will be configured to read these files to determine which replica
processes should be scraped.

This implements the service discovery for metrics as described in [Vector
overview](https://docs.google.com/document/d/1275g6N2ckRVKXJGhclS2wdi0UjA7GCN5DTggnIeAPy8/)

## Quickstart

```shell
mkdir /tmp/{targets,gen}
cargo run -- --targets-dir /tmp/targets --generation-dir /tmp/gen --filter-node-id-regex "^a"
```

The config for Vector will be written to `/tmp/gen`, which
can be inspected to confirm it matches expectations.

## Recommended production configuration

- Specify arguments using flags rather than the configuration file, it's one
  less thing to go wrong.
- Use the following flags
  - `--targets-dir` (Required) to tell the process where to store the info from
    the NNS locally
  - `--generation-dir` (Required) to tell the process where to generate the config
  - `--poll-interval`, set to `10s`, the registry client library doesn't poll
    faster than that.
  - `--metrics-listen-addr IP:PORT`, set to the ip:port to serve metrics on

## Metrics

Prometheus metrics are exported.

The export address is controlled by the `--metrics-listen-addr` flag.

The metrics are:
- `discovery_poll_count` (Counter): Number of times the IC was polled
- `discovery_registries_update_latency_seconds_bucket` (Histogram): Registry
  update latency bucket
- `discovery_registries_update_latency_seconds_sum`  (Counter): Total Registry
  update latency
- `discovery_registries_update_latency_seconds_count` (Counter): Number of
  registry update latency events
- `metrics_endpoint_tcp_connections_total` (Counter): Number of connections done
  to the metrics endpoint

## Safe shutdown

The server shutdowns gracefully on receipt of `SIGINT` (`Ctrl-C`) or `SIGTERM` signal.
