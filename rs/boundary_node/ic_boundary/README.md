# ic-boundary

## Description

The `ic-boundary` is a service that handles all the responsibilities of the API boundary node. It replicates the registry and handles all `api` requests.

## Usage

```sh
ic-boundary                                                          \
    --nns-pub-key-pem                <NNS_KEY_PATH>                  \
    --nns-url                        <NNS_URLS>                      \
    --local-store-path               <LOCAL_STORE_PATH>              \
    --nftables-system-replicas-path  <NFTABLES_SYSTEM_REPLICAS_PATH> \
    --nftables-system-replicas-var   <NFTABLES_SYSTEM_REPLICAS_VAR>  \
    --min_registry_version           <VERSION>                       \
    --min_ok_count                   <OK_COUNT>                      \
    --max_height_lag                 <LAG>                           \
    --metrics-addr                   <METRICS_ADDR>
```
