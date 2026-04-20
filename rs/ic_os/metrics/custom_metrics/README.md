# ic-custom-metrics

Prometheus textfile exporter for a small set of node-local custom metrics.

## Current behavior
- Reads `/proc/interrupts`.
- Finds the `TLB shootdowns` row.
- Sums the per-CPU counters.
- Writes the result as `sum_tlb_shootdowns` using the shared atomic metrics-file
  writer from `ic-os-metrics-utils`.

This crate is intentionally narrow: it currently exports one metric and keeps
all logic in `src/main.rs`.
