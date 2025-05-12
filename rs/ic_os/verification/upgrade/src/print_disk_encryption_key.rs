use anyhow::Result;
use clap::Parser;
use ic_os_upgrade::{DiskEncryptionKeyProvider, Partition};

#[derive(Parser)]
#[command(
    name = "print-disk-encryption-key",
    version,
    about = "Prints encryption key for a specified disk partition",
    long_about = "Utility to print the encryption key for the give partition"
)]
struct Args {
    /// The partition to get encryption key for (var or store)
    #[arg(
        value_enum,
        help = "Specify which partition to get the encryption key for",
        long_help = "Specify which partition to get the encryption key for:\n\
                    - var: Encrypted var partition, private to the current GuestOS version\n\
                    - store: Encrypted store partition, shared between GuestOS releases"
    )]
    partition: Partition,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let provider = DiskEncryptionKeyProvider::new()?;
    print!("{}", provider.get_disk_encryption_key(args.partition)?);
    Ok(())
}
