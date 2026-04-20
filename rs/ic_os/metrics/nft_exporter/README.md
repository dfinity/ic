# nft_exporter

Exports nftables counters as Prometheus textfile metrics.

## How it works
- Executes `nft --json list ruleset`.
- Extracts every `counter` object from the returned JSON ruleset.
- Turns each counter into a Prometheus counter metric and writes the registry to
  the configured textfile path.

The crate is a single-binary utility intended for HostOS metric collection.
