# system-stats-tui

A full-screen terminal UI for displaying real-time system diagnostics on Internet Computer nodes.

## Overview

This tool displays critical system information by sampling local Prometheus exporters (node_exporter, metrics-proxy). 
It's designed to be a read-only monitoring display integrated into the limited-console.

**Displayed metrics include:**
- HostOS/GuestOS versions and block height
- CPU usage breakdown (user, system, iowait, irq, etc.)
- Pressure Stall Information (CPU, I/O, memory)
- Block device I/O statistics
- Network interface status and throughput
- Hardware temperatures

## Usage

```bash
# Monitor localhost (run directly on HostOS)
system_stats_tui

# Monitor a remote node
system_stats_tui -a https://[2a00:fb01:400:44:6800:78ff:fe59:b539]
```

