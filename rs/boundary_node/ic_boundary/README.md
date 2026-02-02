# ic-boundary

## Description

The `ic-boundary` is a service that handles all the responsibilities of the API boundary node. It replicates the registry and handles all `api` requests.

## Usage

To run a minimal `ic-boundary` instance, use the following command:

```sh
ic-boundary                                                          \
    --local-store-path               <LOCAL_STORE_PATH>              \
    --http-port                      <HTTP_PORT>                     \
    --log-stdout
```

Where:
* `<LOCAL_STORE_PATH>` points to a directory where `ic-boundary` will keep the local copy of the registry;
* `<HTTP_PORT>` specifies the port `ic-boundary` is listening on (e.g., `80`);

`ic-boundary` offers many more configuration options. For a full list, run `ic-boundary --help`.
