#!/bin/bash

# Set SEV_ACTIVE environment variable based on systemd-detect-virt output.
# SEV detection involves querying the CPU using cpuid which goes through the HostOS.
# A malicious HostOS could intercept this call. By querying the CPU only once early
# in the boot process and setting an environment variable, each service in the GuestOS
# will see the same value.

case $(systemd-detect-virt --cvm) in
  sev|sev-es|sev-snp)
    echo "SEV_ACTIVE=1"
    ;;
  *)
    echo "SEV_ACTIVE=0"
    ;;
esac
