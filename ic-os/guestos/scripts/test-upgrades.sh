#!/bin/bash

set -e

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..

TMPDIR=$(mktemp -d)

QEMU_PID=
HTTP_PID=
LOCAL_HTTP_PORT=8888
HOST_IP_ADDR=10.11.10.224

LOG_QEMU=$(mktemp)
LOG_BOOT=$(mktemp)
LOG_NNS=$(mktemp)
LOG_UPGRADE=$(mktemp)

function terminate() {
    echo "Terminating"
    [[ -z "$QEMU_PID" ]] || kill -s KILL "$QEMU_PID" || true
    [[ -z "$HTTP_PID" ]] || kill -s KILL "$HTTP_PID" || true

    exit 1
}

trap ctrl_c INT

function ctrl_c() {
    echo "Aborting .. "
    terminate
}

killall --user $(whoami) qemu-system-x86_64 || true

echo "➡️  Preparing image to boot (log at: $LOG_BOOT)"
(
    "${BASE_DIR}"/boot-single-machine-nns.sh $TMPDIR
    "${BASE_DIR}"/scripts/build-disk-image.sh -o /tmp/disk.img
) &>"$LOG_BOOT"

echo "➡️  Preparing image to upgrade to (log at: $LOG_UPGRADE)"
(
    "${BASE_DIR}"/scripts/build-ubuntu.sh -o /tmp/upgrade-image.tar
    OUT=$(mktemp -d)
    (
        cd $OUT
        ls -anh /tmp/upgrade-image.tar
        tar -tf /tmp/upgrade-image.tar
        tar -xf /tmp/upgrade-image.tar
        # Check current file number in image
        echo "cat /opt/ic/share/version.txt" | debugfs root.img -f -

        echo "42" >version.txt
        cat <<EOF | debugfs root.img -w -f -
cd /opt/ic/share
rm version.txt
write version.txt version.txt
EOF

        echo "cat /opt/ic/share/version.txt" | debugfs root.img -f -

        rm version.txt

        tar -czf /tmp/upgrade-image.tar --sparse .

        tar -tf /tmp/upgrade-image.tar
        ls -anh /tmp/upgrade-image.tar

    )
    rm -rf "$OUT"
) &>"$LOG_UPGRADE"

echo "➡️  Starting HTTP server for upgrading"
(
    cd /tmp
    killall --user $(whoami) python3 || true
    python3 -m http.server 8000 --bind ::
) &
HTTP_PID=$!

# Make sure HTTP server comes up.
# Not sure if we still need this.
sleep 10
ss -plant | grep ':\<8000\>'

echo "➡️  Booting image (log at: $LOG_QEMU)"
echo "  SSH access: sshpass -p 'root' ssh root@::1 -p 22222 -o StrictHostKeyChecking=false -o UserKnownHostsFile=/dev/null"
echo "  Log output: sshpass -p 'root' ssh root@::1 -p 22222 -o StrictHostKeyChecking=false -o UserKnownHostsFile=/dev/null journalctl -u dfinity -r"
(
    qemu-system-x86_64 \
        -display none \
        -serial mon:stdio \
        -machine type=q35,accel=kvm \
        -enable-kvm \
        -m 2G \
        -bios /usr/share/OVMF/OVMF_CODE.fd \
        -device virtio-blk-pci,drive=drive0,addr=2.0 \
        -drive file=/tmp/disk.img,format=raw,id=drive0,if=none \
        \
        -device pcie-root-port,id=pcie.1,chassis=1 \
        -netdev user,id=enp1s0,hostfwd=tcp::${LOCAL_HTTP_PORT}-:8080,hostfwd=tcp::22222-:22 \
        -device virtio-net-pci,netdev=enp1s0,bus=pcie.1 \
        \
        -device qemu-xhci \
        -device usb-storage,drive=removable,removable=true \
        -drive file=vm.img,format=raw,id=removable,if=none
) &>"$LOG_QEMU" &
QEMU_PID=$!

NUM=0
echo -n "➡️  Waiting for HTTP server to come up "
while ! curl -s http://[::1]:${LOCAL_HTTP_PORT}; do
    NUM=$(($NUM + 1))
    echo -n "."

    if [[ $NUM -gt 100 ]]; then
        terminate
    fi

    sleep 5
done
echo ""
echo "Replica is up"

echo "➡️  Installing NNS"
(
    "${BASE_DIR}"/scripts/install-nns.sh "$TMPDIR" "http://[::1]:${LOCAL_HTTP_PORT}"
) &>"$LOG_NNS"

echo "➡️  Testing Registry call"
"$TMPDIR"/ic-admin --nns-url http://[::1]:${LOCAL_HTTP_PORT} get-subnet 0 | grep "replica_version"

echo "➡️  Triggering upgrade"
(
    "${BASE_DIR}"/upgrade.sh \
        --nns-url=http://[::1]:${LOCAL_HTTP_PORT} \
        --upgrade-url=http://${HOST_IP_ADDR}:8000/upgrade-image.tar \
        --upgrade-image=/tmp/upgrade-image.tar \
        --version=42
) 2>&1 | tee -a "$LOG_NNS" >/dev/null

NUM=0
echo -n "➡️  Waiting for Upgrade "
while ! grep "Restarting system" "$LOG_QEMU" &>/dev/null; do
    NUM=$(($NUM + 1))
    echo -n "."

    if [[ $NUM -gt 100 ]]; then
        terminate
    fi

    sleep 5
done
echo ""

sleep 15
grep "Welcome.*Ubuntu" "$LOG_QEMU"

NUM=0
echo "➡️  Waiting for version endpoint to change "
while ! curl -s http://[::1]:${LOCAL_HTTP_PORT}/api/v2/status --output - | grep -o "impl_version.[0-9]*" -a; do
    NUM=$(($NUM + 1))

    if [[ $NUM -gt 20 ]]; then
        terminate
    fi

    sleep 5
done

echo "✅ All done - shutting down"
terminate
