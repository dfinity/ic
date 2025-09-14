# guest_disk

The tool contains all logic to handle the formatting and activation of encrypted disk partitions in the GuestOS. The
tool's functionality is exposed through a command-line interface with two main commands: `crypt-format` for initializing
partitions and `crypt-open` for activating them.

We distinguish between two types of partitions:

* **Var Partition**: A private, encrypted partition for the current GuestOS boot alternative and version (gets wiped
  during upgrades).
* **Store Partition**: An encrypted partition that is shared across different GuestOS releases and is kept during
  upgrades.

We employ one of two encryption strategies based on the GuestOS config:

1. **SEV-based Encryption**: When Trusted Execution Environment (TEE) is enabled, the tool derives the disk encryption
   key using AMD SEV which ensures that the disk encryption key is tied to the SEV guest launch measurement. For the
   `store` partition, it includes a mechanism to handle GuestOS upgrades by migrating keys. During an upgrade, it can
   unlock the partition with a previous key, add the new SEV-derived key, and then clean up old keys (implemented in
   `sev.rs`).

2. **Generated Key-based Encryption**: In environments without TEE, the tool falls back to using a generated key. This
   key is stored in `/boot/config/store.keyfile`. If the file doesn't exist, a new 128-bit random key is generated.

Once a partition is successfully opened, it is mapped to a specific path in the `/dev/mapper/` directory. The `var`
partition is mapped to `/dev/mapper/var_crypt`, and the `store` partition to `/dev/mapper/vda10-crypt`.
