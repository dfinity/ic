mkdir /tmp/guestos_upgrade
touch /tmp/guestos_upgrade/upgrade

dd if=/dev/null of=/tmp/guestos_upgrade.img bs=1M seek=10
mkfs.ext4 -F /tmp/guestos_upgrade.img -d /tmp/guestos_upgrade
