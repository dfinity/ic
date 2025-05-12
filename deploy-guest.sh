set -e

target="ic-os/guestos/envs/dev/disk-img.tar.zst"
file="bazel-bin/${target}"
hostos="2a00:fb01:400:44:6800:95ff:fed7:d475"

bazel build ${target}
chmod +w ${file}
scp -o StrictHostKeyChecking=no -6 ${file} admin@[${hostos}]:/tmp

ssh -o StrictHostKeyChecking=no -6 admin@${hostos} << EOF
   sudo systemctl stop monitor-guestos
   sudo systemctl stop guestos
   sudo virsh shutdown guestos-upgrader
   tar xaf /tmp/disk-img.tar.zst -C /tmp disk.img
   sudo dd if=/tmp/disk.img of=/dev/hostlvm/guestos bs=8M conv=sparse
   sudo systemctl start guestos
EOF
