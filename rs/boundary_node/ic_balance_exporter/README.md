# ic-balance-exporter

## Description

The `ic-balance-exporter` is a service that given a list of wallets and a controlling identity for them, will export the balance of the wallets in Prometheus metrics format.

## Usage

```sh
ic-balance-exporter \
    --wallets-path      <WALLETS_PATH> \
    --identity-path     <IDENTITY_PATH> \
    --root-key-path     <ROOT_KEY_PATH> \
    --replica-endpoint  <REPLICA_ENDPOINT> \
    --scrape-interval   <SCRAPE_INTERVAL> \
    --metrics-addr      <METRICS_ADDR>
```
