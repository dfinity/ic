use anyhow::{Context, Result, anyhow, bail, ensure};
use itertools::Itertools;
use pcre2::bytes::Regex;
use std::fs;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::{NamedTempFile, TempDir, tempdir};

use crate::Partition;
use crate::exes::{debugfs, faketime};
use crate::gpt;

const STORE_NAME: &str = "backing_store";

pub struct ExtPartition {
    backing_dir: TempDir,
    original: PathBuf,
    offset_bytes: Option<u64>,
}

impl Partition for ExtPartition {
    /// Open an ext4 partition for writing, via debugfs
    fn open(image: PathBuf, index: Option<u32>) -> Result<Self> {
        let _ = debugfs().context("debugfs is needed to open ext4 partitions")?;

        if let Some(index) = index {
            let offset = gpt::get_partition_offset(&image, index)?;
            let length = gpt::get_partition_length(&image, index)?;
            Self::open_range(image, offset, length)
        } else {
            // open_range is several times slower than fs::copy, therefore we use fs::copy
            // on the fast path if no seeking is necessary.
            let backing_dir = tempdir()?;
            let output_path = backing_dir.path().join(STORE_NAME);
            fs::copy(&image, &output_path)?;
            Ok(ExtPartition {
                backing_dir,
                original: image,
                offset_bytes: None,
            })
        }
    }

    /// Open an ext4 partition for writing, via debugfs, using explicit offset and length
    fn open_range(image: PathBuf, offset_bytes: u64, length_bytes: u64) -> Result<Self> {
        let _ = debugfs().context("debugfs is needed to open ext4 partitions")?;

        let backing_dir = tempdir()?;
        let output_path = backing_dir.path().join(STORE_NAME);

        // Use dd command to copy the specific range, with sparse file support
        ensure!(
            Command::new("dd")
                .args([
                    &format!("if={}", image.display()),
                    &format!("of={}", output_path.display()),
                    "bs=4M",
                    &format!("skip={offset_bytes}"),
                    &format!("count={length_bytes}"),
                    "conv=sparse",
                    "iflag=skip_bytes,count_bytes"
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .context("failed to run dd command")?
                .success()
        );

        Ok(ExtPartition {
            offset_bytes: Some(offset_bytes), // No partition index when using explicit range
            backing_dir,
            original: image,
        })
    }

    /// Close an ext4 partition, and write back to the input disk
    fn close(self) -> Result<()> {
        let input_path = self.backing_dir.path().join(STORE_NAME);
        let output_path = self.original;

        if let Some(offset) = self.offset_bytes {
            let mut input = File::open(&input_path)?;
            let mut output = File::options().write(true).open(&output_path)?;

            output.seek(SeekFrom::Start(offset))?;
            io::copy(&mut input, &mut output)?;
        } else {
            fs::copy(&input_path, &output_path)?;
        }

        Ok(())
    }

    /// Copy a file into place
    fn write_file(&mut self, input: &Path, output: &Path) -> Result<()> {
        let mut cmd = Command::new(faketime().context("faketime is needed to write files")?)
            .args([
                "-f",
                "1970-1-1 0:0:0",
                // debugfs has already been ensured.
                debugfs()
                    .context("debugfs is needed to write files")?
                    .to_str()
                    .unwrap(),
                "-w",
                (self.backing_dir.path().join(STORE_NAME).to_str().unwrap()),
                "-f",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to write file using debugfs")?;

        cmd.stdin
            .as_mut()
            .unwrap()
            .write_all(Self::debugfs_input(input, output).as_bytes())?;
        Self::check_debugfs_result(&cmd.wait_with_output()?)
    }

    /// Read a file from a given partition
    fn read_file(&mut self, input: &Path) -> Result<Vec<u8>> {
        let temp_file = NamedTempFile::new()?;
        self.copy_file_to(input, temp_file.path())?;
        let contents = fs::read(temp_file.path())?;

        Ok(contents)
    }

    fn copy_files_to(&mut self, output: &Path) -> Result<()> {
        ensure!(
            output.exists() && output.is_dir(),
            "output must be an existing directory"
        );

        // Use debugfs to dump the entire filesystem
        let out = Command::new(debugfs().context("debugfs is needed to extract contents")?)
            .args([
                "-R",
                &format!("rdump / {}", output.display()),
                self.backing_dir.path().join(STORE_NAME).to_str().unwrap(),
            ])
            .output()
            .context("failed to run debugfs for extraction")?;

        Self::check_debugfs_result(&out)?;

        Ok(())
    }

    fn copy_file_to(&mut self, from: &Path, to: &Path) -> Result<()> {
        let file_name = from.file_name().expect("`from` must reference a file");

        // When extracting to a directory, use the from filename.
        let dest = if to.is_dir() {
            ensure!(to.exists(), "the path to `to` must already exist");

            &to.join(file_name)
        } else {
            ensure!(
                to.parent().map(|v| v.exists()).unwrap_or(false),
                "the path to `to` must already exist"
            );

            to
        };

        // run the underlying debugfs operation
        // debugfs has already been ensured.
        let mut cmd = Command::new(debugfs().context("debugfs is needed to read files")?)
            .args([
                (self.backing_dir.path().join(STORE_NAME).to_str().unwrap()),
                "-f",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to read file using debugfs")?;

        let mut stdin = cmd.stdin.as_mut().unwrap();
        io::copy(
            &mut indoc::formatdoc!(
                r#"
                cd {path}
                dump {filename} {dest}
            "#,
                path = from.parent().unwrap().to_str().unwrap(),
                filename = from.file_name().unwrap().to_str().unwrap(),
                dest = dest.display(),
            )
            .as_bytes(),
            &mut stdin,
        )?;

        let out = cmd.wait_with_output()?;

        Self::check_debugfs_result(&out)
    }
}

impl ExtPartition {
    /// Clear timestamps, fix ownership, and update security context
    pub fn fixup_metadata(
        &mut self,
        output: &Path,
        mode: usize,
        context: Option<&str>,
    ) -> Result<()> {
        let mut cmd =
            Command::new(faketime().context("faketime is needed to fix metadata in files")?)
                .args([
                    "-f",
                    "1970-1-1 0:0:0",
                    // debugfs has already been ensured.
                    debugfs()
                        .context("debugfs is needed to write files")?
                        .to_str()
                        .unwrap(),
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
        )?;

        let out = cmd.wait_with_output()?;
        if !out.status.success() {
            return Err(anyhow!(
                "debugfs failed: {}",
                String::from_utf8(out.stderr)?
            ));
        }

        Ok(())
    }

    fn check_debugfs_result(out: &Output) -> Result<()> {
        let errors = std::str::from_utf8(&out.stderr)?
            .lines()
            .filter(|error| !error.starts_with("debugfs")) // version number
            // Some errors we ignore.
            .filter(|error| !error.contains("Ext2 directory already exists"))
            .filter(|error| !error.contains("rm: File not found"))
            .filter(|error| !error.contains("Invalid argument while changing ownership"))
            .join("\n");
        if !out.status.success() || !errors.is_empty() {
            bail!("debugfs failed:\n{errors}");
        }

        Ok(())
    }

    fn debugfs_input(input: &Path, output: &Path) -> String {
        // Commands that generate all parent dirs of input (debugfs doesn't
        // support mkdir -p)
        // Eg. if `output` is `/opt/ic/bin/something.txt`, `mkdir_all` will be:
        // mkdir /opt
        // mkdir /opt/ic
        // mkdir /opt/ic/bin
        let mkdir_all = output
            .ancestors()
            .skip(1) // skip `output` itself
            .take_while(|path| path != &Path::new("/"))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|path| format!("mkdir {}", path.display()))
            .join("\n");
        indoc::formatdoc!(
            r#"
            {mkdir_all}
            cd {path}
            rm {filename}
            write {input} {filename}
        "#,
            path = output.parent().unwrap().to_str().unwrap(),
            filename = output.file_name().unwrap().to_str().unwrap(),
            input = &input.to_str().unwrap(),
        )
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
            "/boot_args",
            Some("/boot"),
        );
    }

    #[test]
    fn debugfs_input_test() {
        assert_eq!(
            ExtPartition::debugfs_input(
                Path::new("path/to/input.sh"),
                Path::new("/opt/ic/bin/output.sh")
            ),
            indoc::formatdoc!(
                "mkdir /opt
                 mkdir /opt/ic
                 mkdir /opt/ic/bin
                 cd /opt/ic/bin
                 rm output.sh
                 write path/to/input.sh output.sh
               "
            )
        );
    }

    fn create_empty_partition_img(path: &Path) -> Result<()> {
        Command::new("/usr/bin/dd")
            .args([
                "if=/dev/zero",
                &format!("of={}", path.display()),
                "bs=1K",
                "count=256",
            ])
            .status()?;

        Command::new("/usr/sbin/mkfs.ext4")
            .args([path.as_os_str()])
            .status()?;

        Ok(())
    }

    #[test]
    fn write_read_test() {
        let dir = tempdir().unwrap();
        let img_path = dir.path().join("empty_ext4.img");
        create_empty_partition_img(&img_path)
            .expect("Could not create test partition image");

        let input_file1 = dir.path().join("input.txt");
        let contents1 = b"Hello World!";
        fs::write(input_file1.clone(), contents1).unwrap();

        let input_file2 = dir.path().join("input2.txt");
        let contents2 = b"Foo Bar";
        fs::write(input_file2.clone(), contents2).unwrap();

        let mut partition = ExtPartition::open(img_path.to_path_buf(), None)
            .expect("Could not open partition");

        // Copy a file to the partition.
        let target_path = Path::new("/home/ubuntu/files/out.txt");
        partition
            .write_file(&input_file1, target_path)
            .expect("Could not write file to partition");
        let read = partition
            .read_file(target_path)
            .expect("Could not read file from partition");

        assert_eq!(read, contents1);

        // Overwrite the file that we just created.
        partition
            .write_file(&input_file2, target_path)
            .unwrap();
        let read = partition
            .read_file(target_path)
            .expect("Could not read file from partition");

        assert_eq!(read, contents2);

        // Reading non-existing files should fail.
        assert!(
            partition
                .read_file(Path::new("/does/not/exist.txt"))
                .expect_err("Expected reading non-existing file to fail")
                .to_string()
                .contains("File not found")
        );
    }

    #[test]
    fn copy_files_test() {
        let dir = tempdir().unwrap();
        let img_path = dir.path().join("empty_ext4.img");
        create_empty_partition_img(&img_path)
            .expect("Could not create test partition image");

        let mut partition = ExtPartition::open(img_path.to_path_buf(), None)
            .expect("Could not open partition");

        let input_file_names = ["input.txt", "input2.txt"];
        for file in input_file_names {
            let input_path = dir.path().join(file);
            let output_path = Path::new("/").join(file);
            fs::write(input_path.clone(), b"").unwrap();
            partition
                .write_file(&input_path, &output_path)
                .expect("Could not write file in partition");
        }

        let output_dir = TempDir::new().expect("Could not create temp dir");
        partition.copy_files_to(output_dir.path()).unwrap();

        let mut actual_file_names = std::fs::read_dir(output_dir.path())
            .expect("read_dir failed")
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        actual_file_names.sort();

        assert_eq!(actual_file_names, ["input.txt", "input2.txt", "lost+found"]);
    }

    #[test]
    fn copy_file_test() {
        let dir = tempdir().unwrap();
        let img_path = dir.path().join("empty_ext4.img");
        create_empty_partition_img(&img_path)
            .expect("Could not create test partition image");

        let mut partition = ExtPartition::open(img_path.to_path_buf(), None)
            .expect("Could not open partition");

        let input_file_names = ["input.txt", "input2.txt"];
        for file in input_file_names {
            let input_path = dir.path().join(file);
            let output_path = Path::new("/").join(file);
            fs::write(input_path.clone(), b"").unwrap();
            partition
                .write_file(&input_path, &output_path)
                .expect("Could not write file in partition");
        }

        let output_dir = TempDir::new().expect("Could not create temp dir");

        // Copy with assumed name (from input).
        partition
            .copy_file_to(Path::new("/input.txt"), output_dir.path())
            .unwrap();

        let mut actual_file_names = std::fs::read_dir(output_dir.path())
            .expect("read_dir failed")
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        actual_file_names.sort();

        assert_eq!(actual_file_names, ["input.txt"]);

        // Copy with explicit name (from output).
        partition
            .copy_file_to(
                Path::new("/input2.txt"),
                &output_dir.path().join("different.txt"),
            )
            .unwrap();

        let mut actual_file_names = std::fs::read_dir(output_dir.path())
            .expect("read_dir failed")
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        actual_file_names.sort();

        assert_eq!(actual_file_names, ["different.txt", "input.txt"]);
    }
}
