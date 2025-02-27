input="bazel-bin/ic-os/guestos/envs/dev/disk-img.tar.zst"
hostos="2a00:fb01:400:44:6800:95ff:fed7:d475"

chmod +w ${input}
scp -o StrictHostKeyChecking=no -6 ${input} admin@[${hostos}]:/tmp

ssh -o StrictHostKeyChecking=no -6 admin@${hostos} << EOF
   sudo systemctl stop monitor-guestos
   sudo systemctl stop guestos
   tar xaf /tmp/disk-img.tar.zst -C /tmp disk.img
   sudo dd if=/tmp/disk.img of=/dev/hostlvm/guestos bs=8M
   sudo systemctl start guestos
EOF
