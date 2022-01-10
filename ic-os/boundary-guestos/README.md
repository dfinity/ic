= Boundary Node Guest OS

This contains the build scripts for using system images of Ubuntu
for a Boundary Node as units of deployment.

== Quick build and test instructions (Linux)

To build a full system image, run:

  scripts/build-disk-image.sh -o /tmp/disk.img

A password can be specified with `-p`:

  scripts/build-disk-image.sh -o /tmp/disk.img -p password

This can then be booted with libvirt, e.g.:

  virt-install --disk /tmp/disk.img --import --memory 4096 \
   --os-variant ubuntu20.04 --network bridge=br0,mac=52:54:00:4f:f8:ec \
   --network bridge=vlan66,mac=52:54:00:33:4e:b0 --graphics none \
   --name boundary-guestos --console pty,target.type=virtio \
   --serial pty --boot uefi

You can interact with the VM via the console now (note: issue "ctrl-a", "c"
to enter qemu console from here; issue "quit" to terminate the VM).

== Directory organization

The directory rootfs/ contains everything related to building a bootable
Ubuntu system. It uses various template directories (e.g. /opt) that
are simply copied verbatim to the target system -- you can just drop
files there to include in the image.

The directory bootloader/ contains everything related to building EFI
firmware and the grub bootloader image. 

All build scripts are contained in the scripts/ subdirectory.
