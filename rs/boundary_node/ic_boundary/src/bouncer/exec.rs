use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{Context, Error, bail};
use nftables::schema::Nftables;

const SUDO: &str = "/usr/bin/sudo";
const NFT: &str = "/usr/sbin/nft";

pub trait Execute: Send + Sync {
    fn execute_nftables(&self, payload: &Nftables) -> Result<Option<Nftables>, Error>;
    fn execute_raw(&self, stdin: String) -> Result<String, Error>;
}

// Runs nft binary optionally with sudo and (de-)serializes the stdin/out
#[derive(Clone)]
pub struct Executor {
    sudo: bool,
    sudo_path: String,
    nft_path: String,
}

impl Executor {
    pub fn new(sudo: bool, sudo_path: Option<String>, nft_path: Option<String>) -> Self {
        Self {
            sudo,
            sudo_path: sudo_path.unwrap_or(SUDO.into()),
            nft_path: nft_path.unwrap_or(NFT.into()),
        }
    }
}

impl Execute for Executor {
    fn execute_nftables(&self, payload: &Nftables) -> Result<Option<Nftables>, Error> {
        let payload_raw =
            serde_json::to_string(payload).context("failed to serialize Nftables struct")?;
        let stdout = self.execute_raw(payload_raw)?;

        if !stdout.is_empty() {
            Ok(Some(serde_json::from_str(&stdout).context(
                "failed to deserialize stdout as Nftables struct",
            )?))
        } else {
            Ok(None)
        }
    }

    fn execute_raw(&self, stdin: String) -> Result<String, Error> {
        let (path, mut args) = if self.sudo {
            (&self.sudo_path, vec![self.nft_path.as_str()])
        } else {
            (&self.nft_path, vec![])
        };
        args.extend_from_slice(&["--json", "--file", "-"]);

        // Start the program
        let mut process = Command::new(path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("Failed to spawn command")?;

        // Write stdin
        let mut stdin_handle = process.stdin.take().unwrap();
        stdin_handle.write_all(stdin.as_bytes())?;
        drop(stdin_handle); // Close the stdin to flush

        // Wait for the process to finish
        let result = process.wait_with_output()?;
        if !result.status.success() {
            bail!(
                "Command terminated with non-zero exit code: {}",
                result.status
            );
        }

        let stdout = String::from_utf8(result.stdout)?;
        Ok(stdout)
    }
}
