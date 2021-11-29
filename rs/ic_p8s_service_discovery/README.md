# ic-p8s-service-discovery (p8s = Prometheus)

## Synopsis

Periodically check the registry on a given IC for the current topology
(subnets, and the nodes assigned to them).

When the topology changes it writes a JSON file in [Prometheus file-based
service discovery](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#file_sd_config) format.

Prometheus (see [//infra/monitoring/manifests/prometheus/nix](https://github.com/dfinity-lab/infra/tree/master/monitoring/manifests/prometheus/nix))
is configured to read these files to determine which replica processes should
be scraped.

This implements the "What is the topology of the network" section of [RFC:
Prometheus and IC topology changes](https://docs.google.com/document/d/1nK7Jk2pVn-vRSglzfMVvyqW1oMqyumOc1OXnX7qJo50/edit#heading=h.l5nb4fkfzau5).

## Quickstart

```shell
cargo run -p ic-p8s-service-discovery -- \
  --discover_every 10s \
  --log_level debug \
  --log_to_stderr \
  --log_to_stderr_pretty
  --service_discovery_file /tmp/topology.json \
  --ic_name topochange \
  --nns_urls http://dcs-topochange-11.dfinity.systems:8080
```

Adjust the values of the `--ic_name` and `--nns_urls` flags to reflect the
network you want to check.

The topology for Prometheus will be written to `/tmp/topology.json`, which
can be inspected to confirm it matches expectations.

## General configuration

Configuration can be provided on the command line, a configuration file, or a
mixture of both.

```json
{
  "service_discovery_file": "/tmp/topology.json",
  "service_discovery_file_mode": 416,
  "ic_name": "topochange",
  "metrics_addr": "127.0.0.1:8006",
  "discover_every": "10s",
  "log": {
    "to_stderr": true,
    "to_stderr_pretty": true,
    "level": "debug",
    "to_disk": null
  },
  "nns": {
    "urls": ["http://dcs-topochange-11.dfinity.systems:8080/"]
  }
}
```

Each entry in the config file has an associated command line flag of the
same name (`--ic_name`, `--metrics_addr`, etc). Nested entries are converted
to flags by flattening the nesting and inserting a `_`, so:

```
  "nns": {
    "urls": [
      "http://dcs-topochange-11.dfinity.systems:8080/"
    ]
  }
```

corresponds to `--nns_urls http://...`.

Specify the path to the config file with the `--config_file` flag.

Any command line flags override their values from the config file.

## Recommended production configuration

- Specify arguments using flags rather than the configuration file, it's one
  less thing to go wrong.

- Use the following flags, assuming the server is from `systemd`:
  - `--service_discovery_file`, `ic_name`, `--nns_urls`: Adjust as necessary
    for the IC NNS that is being queried.
  - `--discover_every`, set to `10s`, the registry client library doesn't poll
    faster than that.
  - `--log_level debug`, log at debug and above
  - `--log_to_stderr`, send logs to STDERR
  - `--metrics_addr IP:PORT`, set to the ip:port to serve metrics on
  - Do not set `--log_to_stderr_pretty` or `--log_to_disk PATH` in production

## Logs

Logs are structured JSON, written to files, and can be sent to disk and/or
STDERR.

They follow the Elastic Common Schema definition, see
https://www.elastic.co/guide/en/ecs/current/index.html and the files
in `elastic_common_schema` for more details.

### Logging options

`log_to_disk` -- directory to write logs to.

`log_level` -- minimum level at which to log (`trace`, `debug`, `info`,
`warning`, `error`, `critical`).

`log_to_stderr` -- if true, log messages will be sent to STDERR as well
as to files.

`log_to_stderr_pretty` -- if true, log messages sent to STDERR will be
pretty-printed.

## Metrics

Prometheus metrics are exported.

The export address is controlled by the `--metrics_addr` flag.

The metrics are:

- `ic_service_discovery_duration_seconds` (Histogram): Time elapsed
  from starting to check the registry to finishing writing the topology
  file. `status` label is either `success` for successful checks, or describes
  the failure mode.
- `ic_service_discovery_skipped_total` (Counter): Count of updates skipped
  (not included in `ic_service_discovery_duration_seconds`) because the
  registry version had not changed since the previous iteration.
- `ic_topology_registry_version` (Gauge): Registry version used to determine
  the topology.

## Safe shutdown

The server shutdowns gracefully on receipt of `SIGINT` (`Ctrl-C`) or `SIGTERM` signal.
