use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use pcre2::bytes::Regex;
use tempfile::{tempdir, TempDir};
use tokio::fs;
use tokio::fs::File;
use tokio::io::{self, AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::process::Command;

use crate::partition;
use crate::Partition;

const STORE_NAME: &str = "backing_store";

pub struct ExtPartition {
    index: Option<usize>,
    backing_dir: TempDir,
    original: PathBuf,
}

#[async_trait]
impl Partition for ExtPartition {
    /// Open an ext4 partition for writing, via debugfs
    async fn open(image: PathBuf, index: Option<usize>) -> Result<Self> {
        let backing_dir = tempdir()?;
        let output_path = backing_dir.path().join(STORE_NAME);

        let mut input = File::open(&image).await?;

        if let Some(index) = index {
            let mut output = File::create(output_path).await?;
            let offset = partition::check_offset(&image, index).await?;
            let length = partition::check_length(&image, index).await?;

            input.seek(SeekFrom::Start(offset)).await?;
            io::copy(&mut input.take(length), &mut output).await?;
        } else {
            // Tokio's io::copy is several times slower than fs::copy, therefore we use fs::copy
            // on the fast path if no seeking is necessary.
            fs::copy(&image, &output_path).await?;
        }

        Ok(ExtPartition {
            index,
            backing_dir,
            original: image,
        })
    }

    /// Close an ext4 partition, and write back to the input disk
    async fn close(self) -> Result<()> {
        let input_path = self.backing_dir.path().join(STORE_NAME);
        let output_path = self.original;

        if let Some(index) = self.index {
            let mut input = File::open(&input_path).await?;
            let mut output = File::options().write(true).open(&output_path).await?;
            let offset = partition::check_offset(&output_path, index).await?;

            output.seek(SeekFrom::Start(offset)).await?;
            io::copy(&mut input, &mut output).await?;
        } else {
            // Tokio's io::copy is several times slower than fs::copy, therefore we use fs::copy
            // on the fast path if no seeking is necessary.
            fs::copy(&input_path, &output_path).await?;
        }

        Ok(())
    }

    /// Copy a file into place
    async fn write_file(&mut self, input: &Path, output: &Path) -> Result<()> {
        let mut cmd = Command::new("/usr/bin/faketime")
            .args([
                "-f",
                "1970-1-1 0:0:0",
                "/usr/sbin/debugfs",
                "-w",
                (self.backing_dir.path().join(STORE_NAME).to_str().unwrap()),
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
                path = output.parent().unwrap().to_str().unwrap(),
                filename = output.file_name().unwrap().to_str().unwrap(),
                input = &input.to_str().unwrap(),
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
        let mut cmd = Command::new("/usr/sbin/debugfs")
            .args([
                (self.backing_dir.path().join(STORE_NAME).to_str().unwrap()),
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
                path = input.parent().unwrap().to_str().unwrap(),
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

impl ExtPartition {
    /// Clear timestamps, fix ownership, and update security context
    pub async fn fixup_metadata(
        &mut self,
        output: &Path,
        mode: usize,
        context: Option<&str>,
    ) -> Result<()> {
        let mut cmd = Command::new("/usr/bin/faketime")
            .args([
                "-f",
                "1970-1-1 0:0:0",
                "/usr/sbin/debugfs",
                "-w",
                (self.backing_dir.path().join(STORE_NAME).to_str().unwrap()),
                "-f",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to run debugfs")?;

        let mut stdin = cmd.stdin.as_mut().unwrap();

        let path = output.parent().unwrap().to_str().unwrap();
        let filename = output.file_name().unwrap().to_str().unwrap();
        let context_str = if let Some(context) = context {
            format!("ea_set {filename} security.selinux {context}\000")
        } else {
            "".to_string()
        };

        // Always set root:root, and timestamp 0
        io::copy(
            &mut indoc::formatdoc!(
                r#"
                cd {path}
                set_inode_field {filename} extra_isize 28
                set_inode_field {filename} mode {mode}
                set_inode_field {filename} uid 0
                set_inode_field {filename} gid 0
                set_inode_field {filename} atime 0
                set_inode_field {filename} ctime 0
                set_inode_field {filename} mtime 0
                set_inode_field {filename} crtime 0
                {context_str}
            "#
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
}

pub struct FileContexts {
    map: Vec<(Regex, String)>,
}

impl FileContexts {
    pub fn new(contents: &str) -> Result<Self> {
        let map = contents
            .lines()
            .map(|v| {
                let mut chunks = v.split_whitespace();
                let (pattern, label) = (chunks.next()?, chunks.next_back()?);

                Some((Regex::new(pattern).ok()?, label.to_owned()))
            })
            .collect::<Option<_>>()
            .ok_or(anyhow!("file contexts in unexpected format"))?;

        Ok(Self { map })
    }

    pub fn lookup_context(&self, target: &Path) -> Result<&str> {
        self.map
            .iter()
            .rev()
            .find_map(|(pattern, label)| {
                pattern
                    .is_match(target.to_str()?.as_bytes())
                    .ok()?
                    .then_some(label.as_str())
            })
            .context("no matching context")
    }

    pub fn lookup_context_with_prefix(&self, target: &Path, prefix: &Path) -> Result<&str> {
        let lookup = prefix.join(target.strip_prefix("/")?);

        self.lookup_context(&lookup)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Selected subset of an example SELinux file_contexts file
    const BASIC_CONTEXTS: &str = indoc::indoc!(
        r#"
            /.*     system_u:object_r:default_t:s0
            /etc/.* system_u:object_r:etc_t:s0
            /opt/.* system_u:object_r:usr_t:s0
            /run/.* <<none>>
            /opt/.*\.so     system_u:object_r:lib_t:s0
            /usr/(.*/)?man  -d      system_u:object_r:man_t:s0
            /usr/(.*/)?man/.*       system_u:object_r:man_t:s0
            /opt/(.*/)?bin(/.*)?    system_u:object_r:bin_t:s0
            /opt/(.*/)?lib(/.*)?    system_u:object_r:lib_t:s0
            /opt/(.*/)?man(/.*)?    system_u:object_r:man_t:s0
            /usr/(.*/)?Bin(/.*)?    system_u:object_r:bin_t:s0
            /usr/(.*/)?bin(/.*)?    system_u:object_r:bin_t:s0
            /usr/(.*/)?lib(/.*)?    system_u:object_r:lib_t:s0
            /etc/(x)?inetd\.d/tftp  --      system_u:object_r:tftpd_conf_t:s0
            /boot/.*        system_u:object_r:boot_t:s0
            /opt/ic/bin/replica     --      system_u:object_r:ic_replica_exec_t:s0
        "#
    );

    fn check_lookup(contexts: &FileContexts, left: &str, right: &str, prefix: Option<&str>) {
        let path = Path::new(right);

        let lookup = if let Some(prefix) = prefix {
            contexts
                .lookup_context_with_prefix(path, Path::new(prefix))
                .unwrap()
        } else {
            contexts.lookup_context(path).unwrap()
        };

        assert_eq!(left, lookup)
    }

    #[test]
    fn basic_context_test() {
        let contexts = FileContexts::new(BASIC_CONTEXTS).unwrap();

        check_lookup(
            &contexts,
            "system_u:object_r:usr_t:s0",
            "/opt/ic/share/version.txt",
            None,
        );
        check_lookup(
            &contexts,
            "system_u:object_r:ic_replica_exec_t:s0",
            "/opt/ic/bin/replica",
            None,
        );
        check_lookup(
            &contexts,
            "system_u:object_r:bin_t:s0",
            "/opt/ic/bin/save-machine-id.sh",
            None,
        );
        check_lookup(
            &contexts,
            "system_u:object_r:lib_t:s0",
            "/usr/lib/x86_64-linux-gnu/libnss_icos.so.2",
            None,
        );
        check_lookup(
            &contexts,
            "system_u:object_r:boot_t:s0",
            "/version.txt",
            Some("/boot"),
        );
        check_lookup(
            &contexts,
            "system_u:object_r:boot_t:s0",
            "/extra_boot_args",
            Some("/boot"),
        );
    }
}
