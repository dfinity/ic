# Denylist Updater

The `denylist-updater` is a service that will periodically fetch a canister denylist from the IC and persist that list for use locally.

## Usage

```sh
denylist-updater \
    --remote-url <REMOTE_URL> \
    --local-path <LOCAL_PATH>
```
