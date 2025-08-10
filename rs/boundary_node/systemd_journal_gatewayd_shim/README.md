# systemd-journal-gatewayd-shim

A Rust application that acts as a shim for `systemd-journal-gatewayd`, providing log access for specific systemd units.

## Overview

`systemd-journal-gatewayd-shim` is a Rust application designed to serve as a shim for [`systemd-journal-gatewayd`](https://www.freedesktop.org/software/systemd/man/systemd-journal-gatewayd.service.html), providing log access for specific systemd units. It acts as an intermediary between clients and the systemd journal, allowing controlled access to logs.

## Usage

The application can be configured using command-line arguments:

```
--addr: Address for serving requests. Default is 127.0.0.1:19532.
--upstream: URL of the systemd-journal-gatewayd instance. Default is http://localhost:19531/.
--units: List of systemd units to allow log access for. Separate multiple units with commas. Default is an empty list.
```
