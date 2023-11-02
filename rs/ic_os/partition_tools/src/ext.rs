use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tempfile::{tempdir, TempDir};
use tokio::fs::File;
use tokio::io::{self, AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::process::Command;

use crate::partition;
use crate::Partition;

const STORE_NAME: &str = "backing_store";

pub struct ExtPartition {
    index: usize,
    backing_dir: TempDir,
    original: PathBuf,
}

#[async_trait]
impl Partition for ExtPartition {
    /// Open an ext4 partition for writing, via debugfs
    async fn open(image: PathBuf, index: usize) -> Result<Self> {
        let backing_dir = tempdir()?;

        let offset = partition::check_offset(&image, index).await?;
        let length = partition::check_length(&image, index).await?;

        let mut input = File::open(&image).await?;
        input.seek(SeekFrom::Start(offset)).await?;
        let mut output = File::create(backing_dir.path().join(STORE_NAME)).await?;

        io::copy(&mut input.take(length), &mut output).await?;

        Ok(ExtPartition {
            index,
            backing_dir,
            original: image,
        })
    }

    /// Close an ext4 partition, and write back to the input disk
    async fn close(self) -> Result<()> {
        let offset = partition::check_offset(&self.original, self.index).await?;

        let mut input = File::open(&self.backing_dir.path().join(STORE_NAME)).await?;
        let mut output = File::options().write(true).open(&self.original).await?;
        output.seek(SeekFrom::Start(offset)).await?;

        io::copy(&mut input, &mut output).await?;

        Ok(())
    }

    /// Copy a file into place
    async fn write_file(&mut self, input: &Path, output: &Path) -> Result<()> {
        let mut cmd = Command::new("debugfs")
            .args([
                "-w",
                &self
                    .backing_dir
                    .path()
                    .join(STORE_NAME)
                    .display()
                    .to_string(),
                "-f",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to run debugfs")?;

        let mut stdin = cmd.stdin.as_mut().unwrap();
        io::copy(
            &mut indoc::formatdoc!(
                r#"
                cd {path}
                rm {filename}
                write {input} {filename}
            "#,
                path = output.parent().unwrap().display(),
                filename = output.file_name().unwrap().to_str().unwrap(),
                input = &input.display().to_string(),
            )
            .as_bytes(),
            &mut stdin,
        )
        .await?;

        let out = cmd.wait_with_output().await?;
        if !out.status.success() {
            return Err(anyhow!(
                "debugfs failed: {}",
                String::from_utf8(out.stderr)?
            ));
        }

        Ok(())
    }

    /// Read a file from a given partition
    async fn read_file(&mut self, input: &Path) -> Result<String> {
        // run the underlying debugfs operation
        let mut cmd = Command::new("debugfs")
            .args([
                &self
                    .backing_dir
                    .path()
                    .join(STORE_NAME)
                    .display()
                    .to_string(),
                "-f",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to run debugfs")?;

        let mut stdin = cmd.stdin.as_mut().unwrap();
        io::copy(
            &mut indoc::formatdoc!(
                r#"
                cd {path}
                cat {filename}
            "#,
                path = input.parent().unwrap().display(),
                filename = input.file_name().unwrap().to_str().unwrap(),
            )
            .as_bytes(),
            &mut stdin,
        )
        .await?;

        let out = cmd.wait_with_output().await?;
        if !out.status.success() {
            return Err(anyhow!(
                "debugfs failed: {}",
                String::from_utf8(out.stderr)?
            ));
        }

        let cleaned_output = std::str::from_utf8(&out.stdout)?
            .lines()
            .skip(2)
            .collect::<Vec<_>>()
            .join("\n");

        Ok(cleaned_output)
    }
}
