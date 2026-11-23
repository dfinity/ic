#!/usr/bin/env bash
# Validation only, not for merging: a TEE GuestOS installs no SSH keys, so this reads its memory
# from its metrics and its kernel log from HostOS (HOSTOS_IP, set by deploy.py).
set -uo pipefail

ssh_key="${2}"
guest="${3}"
O=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30)
if [ "${ssh_key}" != "None" ]; then
    O+=(-i "${ssh_key}")
fi

read -r -d '' PY <<'EOF'
import re, sys
vals, free = {}, 0.0
for line in sys.stdin:
    m = re.match(r'node_buddyinfo_blocks\{[^}]*size="(\d+)"[^}]*\} (\S+)', line)
    if m:
        free += float(m.group(2)) * 4096 * 2 ** int(m.group(1))
        continue
    m = re.match(r'(node_memory_(?:MemTotal|MemFree|MemAvailable|Cached|Unaccepted)_bytes|node_boot_time_seconds|node_time_seconds|guestos_tee_active)(?:\{[^}]*\})? (\S+)', line)
    if m:
        vals[m.group(1)] = float(m.group(2))
for k, v in sorted(vals.items()):
    print(f"{k}: {v / 2**30:.2f} GiB" if k.endswith("_bytes") else f"{k}: {v:.0f}")
print(f"free lists (buddyinfo): {free / 2**30:.2f} GiB")
mf = vals.get("node_memory_MemFree_bytes")
if mf is not None:
    print(f"MemFree - free lists: {(mf - free) / 2**30:.2f} GiB")
if "node_time_seconds" in vals and "node_boot_time_seconds" in vals:
    print(f"uptime: {vals['node_time_seconds'] - vals['node_boot_time_seconds']:.0f} s")
EOF

guest_memory() {
    echo "---- GuestOS memory ($(date -u +%FT%TZ))"
    curl -sk --max-time 60 "https://[${guest}]:9100/metrics" | python3 -c "${PY}"
}

echo "-------------------- TEE probe --------------------"
guest_memory
# Every 15 s for 20 minutes: acceptance (down to the service's 16 GiB), then whether the guest
# stays up with the memory free.
for i in $(seq 1 80); do
    m=$(curl -sk --max-time 60 "https://[${guest}]:9100/metrics" | python3 -c "${PY}")
    echo "$(date -u +%FT%TZ) $(echo "${m}" | grep -E '^(MemFree - free lists|free lists|uptime)' | paste -sd ';')"
    sleep 15
done
guest_memory
echo "---- HostOS ${HOSTOS_IP}"
ssh "${O[@]}" "admin@${HOSTOS_IP}" sudo bash -s <<'EOF'
cd /var/log/libvirt/qemu && ls -la
for f in *serial*; do
    echo "== ${f}"
    grep -a -E 'Linux version|Command line|Memory:|SEV|[Uu]naccepted|accept|deferred pages|Freeing unused kernel|Run /|Startup finished|Finished|BOOT FAILURE' "${f}" | grep -a -v 'Job accept-memory' | tail -60
done
for f in *.log; do
    case "${f}" in *serial*) continue ;; esac
    echo "== ${f}"
    grep -a -E 'starting up|shutting down|terminating' "${f}" | tail -6
done
virsh list --all
for d in $(virsh list --name); do
    virsh dominfo "${d}"
    virsh dumpxml "${d}" | grep -E '<memory|<currentMemory|<vcpu|launchSecurity|<policy|<cmdline' | cut -c1-400
done
free -g
journalctl -u guestos.service -o short-iso --no-pager | tail -30
EOF
guest_memory
echo "---------------------------------------------------"
