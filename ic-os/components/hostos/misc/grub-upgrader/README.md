# GRUB Upgrader

`grub-upgrader` propagates GRUB configuration updates from the boot partition 
to the GRUB partition after IC-OS upgrades.

## How It Works

HostOS and GuestOS upgrade images include the latest `grub.cfg` on the boot partition (`/boot/grub.cfg`),
but GRUB reads from the GRUB partition (`/boot/grub/grub.cfg`).
This service syncs them by copying `/boot/grub.cfg` to `/boot/grub/grub.cfg`.

## ⚠️ Backwards Compatibility

If enabling this service, ensure the latest `grub.cfg` is backwards
compatible with existing GRUB EFI binaries on mainnet.
This service only updates the config file—not the GRUB EFI binary.
New syntax unsupported by older GRUB versions may cause boot failures.
