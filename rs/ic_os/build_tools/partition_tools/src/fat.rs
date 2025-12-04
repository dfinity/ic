use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, ensure};

use crate::Partition;
use crate::gpt;

pub struct FatPartition {
    offset_bytes: Option<u64>,
    original: PathBuf,
}

impl Partition for FatPartition {
    /// Open a fat3 partition for writing, via mtools. There is nothing to do
    /// here, as mtools works in place.
    fn open(image: PathBuf, index: Option<u32>) -> Result<Self> {
        let mut offset = None;
        if let Some(index) = index {
            offset = Some(gpt::get_partition_offset(&image, index)?);
        }
        Ok(FatPartition {
            offset_bytes: offset,
            original: image,
        })
    }

    fn open_range(image: PathBuf, offset_bytes: u64, _length_bytes: u64) -> Result<Self> {
        Ok(Self {
            offset_bytes: Some(offset_bytes),
            original: image,
        })
    }

    /// Close a fat32 partition. There is nothing to do here, as mtools works
    /// in place.
    fn close(self) -> Result<()> {
        Ok(())
    }

    /// Copy a file into place
    fn write_file(&mut self, input: &Path, output: &Path) -> Result<()> {
        let out = if let Some(offset) = self.offset_bytes {
            Command::new("mcopy")
                .args([
                    "-o",
                    "-i",
                    &format!("{}@@{}", self.original.display(), offset),
                    &input.display().to_string(),
                    &format!("::{}", output.display()),
                ])
                .output()
                .context("failed to run mcopy")?
        } else {
            Command::new("mcopy")
                .args([
                    "-o",
                    "-i",
                    &self.original.display().to_string(),
                    &input.display().to_string(),
                    &format!("::{}", output.display()),
                ])
                .output()
                .context("failed to run mcopy")?
        };

        if !out.status.success() {
            return Err(anyhow!("mcopy failed: {}", String::from_utf8(out.stderr)?));
        }

        Ok(())
    }

    /// Read a file from a given partition
    fn read_file(&mut self, input: &Path) -> Result<Vec<u8>> {
        self.copy_file_inner(input, Path::new("-"))
    }

    fn copy_files_to(&mut self, output: &Path) -> Result<()> {
        ensure!(
            output.exists() && output.is_dir(),
            "output must be an existing directory"
        );

        let out = if let Some(offset) = self.offset_bytes {
            Command::new("mcopy")
                .args([
                    "-s", // recursive copy
                    "-o", // overwrite existing files
                    "-i",
                    &format!("{}@@{}", self.original.display(), offset),
                    "::/", // copy everything from root of FAT partition
                    &output.display().to_string(),
                ])
                .output()
                .context("failed to run mcopy")?
        } else {
            Command::new("mcopy")
                .args([
                    "-s", // recursive copy
                    "-o", // overwrite existing files
                    "-i",
                    &self.original.display().to_string(),
                    "::/", // copy everything from root of FAT partition
                    &output.display().to_string(),
                ])
                .output()
                .context("failed to run mcopy")?
        };

        if !out.status.success() {
            return Err(anyhow!("mcopy failed: {}", String::from_utf8(out.stderr)?));
        }

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

        ensure!(
            dest.parent().map(|v| v.exists()).unwrap_or(false),
            "the path to `to` must already exist"
        );

        let _stdout = self.copy_file_inner(from, dest)?;

        Ok(())
    }
}

impl FatPartition {
    // Capture and return stdout, which may be used to "read" the file directly
    fn copy_file_inner(&mut self, from: &Path, to: &Path) -> Result<Vec<u8>> {
        let out = if let Some(offset) = self.offset_bytes {
            Command::new("mcopy")
                .args([
                    "-o",
                    "-i",
                    &format!("{}@@{}", self.original.display(), offset),
                    &format!("::{}", from.display()),
                    &format!("{}", to.display()),
                ])
                .output()
                .context("failed to run mcopy")?
        } else {
            Command::new("mcopy")
                .args([
                    "-o",
                    "-i",
                    &format!("{}", self.original.display()),
                    &format!("::{}", from.display()),
                    &format!("{}", to.display()),
                ])
                .output()
                .context("failed to run mcopy")?
        };

        if !out.status.success() {
            return Err(anyhow!("mcopy failed: {}", String::from_utf8(out.stderr)?));
        }

        Ok(out.stdout)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs;
    use tempfile::{TempDir, tempdir};

    fn create_empty_partition_img(path: &Path) -> Result<()> {
        Command::new("/usr/bin/dd")
            .args([
                "if=/dev/zero",
                &format!("of={}", path.display()),
                "bs=1K",
                "count=256",
            ])
            .status()?;

        Command::new("/usr/sbin/mkfs.fat")
            .args(["-F", "32", "-i", "0"])
            .arg(path.as_os_str())
            .status()?;

        Ok(())
    }

    #[test]
    fn write_read_test() {
        let dir = tempdir().unwrap();
        let img_path = dir.path().join("empty_fat32.img");
        create_empty_partition_img(&img_path).expect("Could not create test partition image");

        let input_file1 = dir.path().join("input.txt");
        let contents1 = b"Hello World!";
        fs::write(input_file1.clone(), contents1).unwrap();

        let input_file2 = dir.path().join("input2.txt");
        let contents2 = b"Foo Bar";
        fs::write(input_file2.clone(), contents2).unwrap();

        let mut partition =
            FatPartition::open(img_path.to_path_buf(), None).expect("Could not open partition");

        // Copy a file to the partition.

        // TODO: Support creating directories if they do not already exist. Needs to be smarter than ext impl because:
        // > Mmd makes a new directory on an MS-DOS file system. An error occurs if the directory already exists.
        // let target_path = Path::new("/home/ubuntu/files/out.txt");
        let target_path = Path::new("out.txt");

        partition
            .write_file(&input_file1, target_path)
            .expect("Could not write file to partition");
        let read = partition
            .read_file(target_path)
            .expect("Could not read file from partition");

        assert_eq!(read, contents1);

        // Overwrite the file that we just created.
        partition.write_file(&input_file2, target_path).unwrap();
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
                .contains("not found")
        );
    }

    #[test]
    fn copy_files_test() {
        let dir = tempdir().unwrap();
        let img_path = dir.path().join("empty_fat32.img");
        create_empty_partition_img(&img_path).expect("Could not create test partition image");

        let mut partition =
            FatPartition::open(img_path.to_path_buf(), None).expect("Could not open partition");

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

        assert_eq!(actual_file_names, ["input.txt", "input2.txt"]);
    }

    #[test]
    fn copy_file_test() {
        let dir = tempdir().unwrap();
        let img_path = dir.path().join("empty_fat32.img");
        create_empty_partition_img(&img_path).expect("Could not create test partition image");

        let mut partition =
            FatPartition::open(img_path.to_path_buf(), None).expect("Could not open partition");

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
