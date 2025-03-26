# canary-proxy

## Description

The `canary-proxy` is an HTTP proxy service that forwards all traffic to a specific address (usually `localhost`).

Essentially this acts as a blackhole DNS on the proxy server side, regardless of the requested domain.

## Usage

```sh
canary-proxy --listen-port 8888 --target-host 127.0.0.1:0
```

# `*.pac`

A Proxy Auto Config file which should enable easy use of the canary. This config file conditionally proxies requests based on their domain.

This file needs to be maintained with a list of all BN hosted domains we are interested in testing on the canary.

This file should be hosted somewhere easily accessible (with the mime type `application/x-ns-proxy-autoconfig`).

Third parties can host their own modified copies of this `pac` file with the BN hosted domains they are interested in testing.

Two versions are provided here:
* `canary-fallback.pac` tries the canary but falls back to direct connections if the canary proxy is down
* `force-canary.pac` does not fallback, meaning connections to IC sites should timeout if the canary proxy is down
