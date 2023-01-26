# IS-OS

## Running SEV-SNP VM with virsh

### Preparing dev Machine

Here are the steps to run a BN image as a SEV-SNP image
* Download the latest snp release from here: https://github.com/dfinity/AMDSEV/releases/tag/snp-release-2022-08-02
* Install the host kernel and reboot the machine
* Make sure that SEV-SNP is enabled on the host. By runnign this command:
```bash
ubuntu@sf1-gby01:~/AMDSEV/snp-release-2022-04-15$ sudo dmesg | grep  -i -e sev -e ccp -e rmp
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.14.0-rc2-snp-host-6d4469b86f90 root=/dev/mapper/vgroot-lvroot ro mem_encrypt=on kvm_amd.sev=1 amd_iommu=on
[    0.520036] Kernel command line: BOOT_IMAGE=/boot/vmlinuz-5.14.0-rc2-snp-host-6d4469b86f90 root=/dev/mapper/vgroot-lvroot ro mem_encrypt=on kvm_amd.sev=1 amd_iommu=on
[    1.768903] SEV-SNP: RMP table physical address 0x0000007fef500000 - 0x000000806fcfffff
[    2.767472] [Hardware Error]: event severity: fatal
[    8.328990] ccp 0000:22:00.1: enabling device (0000 -> 0002)
[    8.330886] ccp 0000:22:00.1: no command queues available
[    8.331699] ccp 0000:22:00.1: sev enabled
[    8.331702] ccp 0000:22:00.1: psp enabled
[    8.331973] ccp 0000:a6:00.1: enabling device (0000 -> 0002)
[    8.333711] ccp 0000:a6:00.1: no command queues available
[    8.382289] ccp 0000:22:00.1: SEV firmware update successful
[   17.253755] ccp 0000:22:00.1: SEV-SNP API:1.51 build:3
[   17.267208] SEV supported: 410 ASIDs
[   17.267209] SEV-ES and SEV-SNP supported: 99 ASIDs
```

### Preparing image

* cd to the root of the source tree
* build the image: bazel build //ic-os/boundary-guestos/envs/dev-sev/...
* ic-os/scripts/prepare-for-virsh.sh

### Create, login, destroy

* ```$ virsh create ./bn_sev_vm.xml```
* ```$ virsh console boundary_nodes_sev_snp-$USER```
* "control-] to exit"
* ```$ virsh destoy boundary_nodes_sev_snp-$USER```
