#!/bin/bash

# Set SEV_ACTIVE environment variable based on systemd-detect-virt output.
# SEV detection involves querying the CPU using cpuid which goes through the HostOS.
# A malicious HostOS could intercept this call, but by querying the CPU only once early
# in the boot process and setting an environment variable, each service in the GuestOS
# will see the same value. Therefore, faking the initial cpuid is not an attack vector,
# as it would not allow selective manipulation of SEV status between services — it is
# equivalent of enabling/disabling SEV in the GuestOS VM config.

case $(systemd-detect-virt --cvm) in
  sev|sev-es|sev-snp)
    echo "SEV_ACTIVE=1"
    ;;
  *)
    echo "SEV_ACTIVE=0"
    ;;
esac
