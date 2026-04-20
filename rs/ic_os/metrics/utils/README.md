# ic-os-metrics-utils

Shared helpers for IC-OS metrics exporters.

## What it does
- Encodes a Prometheus `Registry` with the text encoder.
- Writes the rendered metrics atomically via a temporary file and rename.

Use this crate from small exporters so they all get the same safe textfile
writer behavior.
