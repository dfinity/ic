//! Generate and write private and public keys for IC admins and users.
//!
//! Usage:
//!
//! ic-identity --out-dir foo/bar/baz/ --name dc_A
//!
//! This will create dc_A_secret.pem and dc_A_public.der in foo/bar/baz.
//!
//! ```

use anyhow::Result;
use clap::Clap;
use std::fs;
use std::path::PathBuf;

use ic_identity::generate_key;

#[derive(Clap)]
#[clap(version = "0.1.0", author = "DFINITY team <team@dfinity.org>")]
struct Opts {
    #[clap(
        short = 'd',
        long,
        about = "The path of the directory in which the keys will be stored.",
        default_value = "."
    )]
    out_dir: PathBuf,

    #[clap(
        short = 'n',
        long,
        about = "The name of the key.",
        default_value = "identity"
    )]
    name: String,
}

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    if !opts.out_dir.exists() {
        fs::create_dir_all(opts.out_dir.as_path()).expect("Couldn't create the output directory");
    }

    let (secret_pem, public_der) = generate_key();

    let secret_pem_file = opts.out_dir.join(format!("{}_secret.pem", opts.name));
    fs::write(&secret_pem_file, secret_pem.into_bytes())?;

    let public_der_file = opts.out_dir.join(format!("{}_public.der", opts.name));
    fs::write(&public_der_file, public_der)?;

    let mut permissions = fs::metadata(&secret_pem_file)?.permissions();
    permissions.set_readonly(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o400);
    }

    fs::set_permissions(&secret_pem_file, permissions)?;

    Ok(())
}
