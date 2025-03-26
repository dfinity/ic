mkdir /tmp/guestos_type
touch /tmp/guestos_type/upgrade
touch /tmp/guestos_type/default

dd if=/dev/zero of=/tmp/guestos_type/default.img bs=1M count=2
dd if=/dev/zero of=/tmp/guestos_type/upgrade.img bs=1M count=2

mkfs.vfat /tmp/guestos_type/default.img -F 32
mkfs.vfat /tmp/guestos_type/upgrade.img -F 32

mcopy -i /tmp/guestos_type/default.img /tmp/guestos_type/default ::
mcopy -i /tmp/guestos_type/upgrade.img /tmp/guestos_type/upgrade ::

mlabel -i /tmp/guestos_type/default.img ::VM_TYPE
mlabel -i /tmp/guestos_type/upgrade.img ::VM_TYPE

