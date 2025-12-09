#![cfg(test)]

use crate::fat::fat_min_time;
use crate::{Args, OutputType, build_filesystem};
use ic_device::mount::{FileSystem, LoopDeviceMounter, MountOptions, Mounter};
use proptest::prelude::*;
use std::fs;
use std::io::Read;
use std::ops::Add;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

fn get_mke2fs_path() -> PathBuf {
    PathBuf::from(std::env::var("MKE2FS_BIN").unwrap())
}

/// Test fixture for creating filesystem images and mounting them
struct ImageFixture {
    /// The path where the image/tar is generated
    output_path: PathBuf,
    output_type: OutputType,
    /// Temporary directory for intermediate files
    temp_dir: TempDir,
}

/// Builder for creating ImageFixture with custom arguments
struct ImageFixtureBuilder {
    output_type: OutputType,
    partition_size: Option<String>,
    label: Option<String>,
    subdir: Option<PathBuf>,
    file_contexts: Option<PathBuf>,
    strip_paths: Vec<String>,
    extra_files: Vec<String>,
    tar_builder: Option<tar::Builder<Vec<u8>>>,
}

impl ImageFixtureBuilder {
    fn new(output_type: OutputType) -> Self {
        Self {
            output_type,
            partition_size: None,
            label: None,
            subdir: None,
            file_contexts: None,
            strip_paths: Vec::new(),
            extra_files: Vec::new(),
            tar_builder: None,
        }
    }

    fn partition_size(mut self, size: &str) -> Self {
        self.partition_size = Some(size.to_string());
        self
    }

    fn partition_size_if_not_tar(mut self, size: &str) -> Self {
        if self.output_type != OutputType::Tar {
            self.partition_size = Some(size.to_string());
        }
        self
    }

    fn label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }

    fn subdir(mut self, subdir: &str) -> Self {
        self.subdir = Some(PathBuf::from(subdir));
        self
    }

    fn file_contexts(mut self, path: PathBuf) -> Self {
        self.file_contexts = Some(path);
        self
    }

    fn strip_path(mut self, path: &str) -> Self {
        self.strip_paths.push(path.to_string());
        self
    }

    fn extra_file(mut self, file: &str) -> Self {
        self.extra_files.push(file.to_string());
        self
    }

    fn tar_content(mut self, builder: tar::Builder<Vec<u8>>) -> Self {
        self.tar_builder = Some(builder);
        self
    }

    fn build(self) -> ImageFixture {
        let temp_dir = TempDir::new().unwrap();
        let output_path = match self.output_type {
            OutputType::Tar => temp_dir.path().join("output.tar"),
            OutputType::Ext4 | OutputType::Vfat | OutputType::Fat32 => {
                temp_dir.path().join("output.img")
            }
        };

        let input_tar = if let Some(builder) = self.tar_builder {
            let tar_data = builder.into_inner().unwrap();
            let tar_path = temp_dir.path().join("input.tar");
            fs::write(&tar_path, tar_data).unwrap();
            Some(tar_path)
        } else {
            None
        };

        build_filesystem(Args {
            output: output_path.clone(),
            input: input_tar,
            output_type: self.output_type,
            partition_size: self
                .partition_size
                .as_ref()
                .map(|s| s.parse())
                .transpose()
                .unwrap(),
            label: self.label,
            subdir: self.subdir,
            file_contexts: self.file_contexts,
            strip_paths: self.strip_paths,
            extra_files: self.extra_files,
            mke2fs_path: Some(get_mke2fs_path()),
        })
        .unwrap();

        ImageFixture {
            temp_dir,
            output_path,
            output_type: self.output_type,
        }
    }
}

impl ImageFixture {
    fn builder(output_type: OutputType) -> ImageFixtureBuilder {
        ImageFixtureBuilder::new(output_type)
    }

    fn path(&self) -> &Path {
        &self.output_path
    }

    /// Convert OutputType to FileSystem for mounting
    fn filesystem_type(&self) -> FileSystem {
        match self.output_type {
            OutputType::Ext4 => FileSystem::Ext4,
            OutputType::Vfat | OutputType::Fat32 => FileSystem::Vfat,
            OutputType::Tar => panic!("No filesystem type for tar"),
        }
    }

    /// Mount the image (Linux only)
    /// For tar files, this extracts the tar to a temporary directory
    /// For filesystem images, this mounts them using a loop device
    fn mount(&self) -> MountedImage {
        match self.output_type {
            OutputType::Tar => MountedImage::extract_tar(self.path()),
            _ => MountedImage::mount_loop(self.path(), self.filesystem_type()),
        }
    }

    /// Extract tar.zst and return path to extracted tar
    fn extract_zst(&self) -> PathBuf {
        use std::process::Command;

        let extracted = self.temp_dir.path().join("extracted.tar");

        let output = Command::new("zstd")
            .arg("-d")
            .arg(self.path())
            .arg("-o")
            .arg(&extracted)
            .output()
            .unwrap();

        assert!(output.status.success(), "zstd decompression failed");

        extracted
    }
}

/// Helper to mount an image and verify contents
/// For tar files, this extracts to a temp directory
/// For filesystem images, this mounts using a loop device
struct MountedImage {
    // The mount point points to either the mount or the temp dir
    mount_point: PathBuf,
    _mount: Option<Box<dyn ic_device::mount::MountedPartition>>,
    _temp_dir: Option<TempDir>,
}

impl MountedImage {
    /// Mount a filesystem image using a loop device
    fn mount_loop(image_path: &Path, fs_type: FileSystem) -> Self {
        assert!(
            image_path.exists(),
            "Image file does not exist: {}",
            image_path.display()
        );

        let mount = LoopDeviceMounter
            .mount_range(
                image_path.to_path_buf(),
                0,
                fs::metadata(image_path).unwrap().len(),
                MountOptions {
                    file_system: fs_type,
                },
            )
            .unwrap();

        let mount_point = mount.mount_point().to_path_buf();

        Self {
            mount_point,
            _mount: Some(mount),
            _temp_dir: None,
        }
    }

    /// Extract a tar file to a temporary directory
    fn extract_tar(tar_path: &Path) -> Self {
        use std::process::Command;

        let temp_dir = TempDir::new().unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir(&extract_dir).unwrap();

        let output = Command::new("tar")
            .arg("-xf")
            .arg(tar_path)
            .arg("-C")
            .arg(&extract_dir)
            .output()
            .unwrap();

        assert!(output.status.success(), "tar extraction failed");

        Self {
            mount_point: extract_dir,
            _mount: None,
            _temp_dir: Some(temp_dir),
        }
    }

    fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Assert file exists with expected content
    fn assert_file_content(&self, path: &str, expected: &str) {
        let file_path = self.mount_point().join(path);
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, expected, "File {} has wrong content", path);
    }

    /// Assert file exists
    fn assert_file_exists(&self, path: &str) {
        let file_path = self.mount_point().join(path);
        assert!(file_path.exists(), "File {} does not exist", path);
    }

    /// Assert file does not exist
    fn assert_file_not_exists(&self, path: &str) {
        let file_path = self.mount_point().join(path);
        assert!(!file_path.exists(), "File {} should not exist", path);
    }

    /// Assert directory exists
    fn assert_dir_exists(&self, path: &str) {
        let dir_path = self.mount_point().join(path);
        assert!(dir_path.is_dir(), "Directory {} does not exist", path);
    }

    /// Assert file has specific permissions
    fn assert_permissions(&self, path: &str, expected_mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let file_path = self.mount_point().join(path);
        let metadata = fs::metadata(&file_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, expected_mode,
            "File {} has wrong permissions: {:o} (expected {:o})",
            path, mode, expected_mode
        );
    }

    /// Assert file has specific ownership
    fn assert_ownership(&self, path: &str, expected_uid: u32, expected_gid: u32) {
        use std::os::unix::fs::MetadataExt;
        let file_path = self.mount_point().join(path);
        let metadata = fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.uid(), expected_uid, "File {} has wrong uid", path);
        assert_eq!(metadata.gid(), expected_gid, "File {} has wrong gid", path);
    }
}

fn all_types() -> impl Strategy<Value = OutputType> {
    prop_oneof![
        Just(OutputType::Tar),
        Just(OutputType::Ext4),
        Just(OutputType::Vfat),
        Just(OutputType::Fat32),
    ]
}

fn append_file(tar: &mut tar::Builder<Vec<u8>>, path: &str, content: &[u8], mode: u32) {
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    tar.append_data(&mut header, path, content).unwrap();
}

fn append_dir(tar: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(mode);
    header.set_cksum();
    tar.append_data(&mut header, path, &[] as &[u8]).unwrap();
}

proptest! {
    #[test]
    fn test_basic_files_and_dirs(output_type in all_types()) {
        let mut tar = tar::Builder::new(Vec::new());

        append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);
        append_dir(&mut tar, "subdir", 0o755);
        append_file(&mut tar, "subdir/file2.txt", "nested content".as_bytes(), 0o644);
        append_dir(&mut tar, "emptydir", 0o755);

        let mut builder = ImageFixture::builder(output_type).tar_content(tar);

        if output_type != OutputType::Tar {
            builder = builder.partition_size("50M");
        }

        let image = builder.build();
        let mounted = image.mount();

        mounted.assert_file_content("file1.txt", "test content");
        mounted.assert_file_content("subdir/file2.txt", "nested content");
        mounted.assert_dir_exists("emptydir");
        mounted.assert_dir_exists("subdir");
    }

    #[test]
    fn test_label(output_type in prop_oneof![Just(OutputType::Vfat), Just(OutputType::Fat32)]) {
        let mut tar = tar::Builder::new(Vec::new());
        append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);

        let image = ImageFixture::builder(output_type)
            .partition_size("50M")
            .label("TESTLABEL")
            .tar_content(tar)
            .build();

        let output_label = std::process::Command::new("blkid")
            .arg("-s")
            .arg("LABEL")
            .arg("-o")
            .arg("value")
            .arg(image.path())
            .output()
            .expect("failed to start blkid");
        let label = String::from_utf8_lossy(&output_label.stdout)
            .trim()
            .to_string();
        assert_eq!(label, "TESTLABEL", "Label should match");

        let mounted = image.mount();
        mounted.assert_file_content("file1.txt", "test content");
    }

    #[test]
    fn test_subdir_extraction(output_type in all_types()) {
        let mut tar = tar::Builder::new(Vec::new());

        append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);
        append_file(&mut tar, "subdir/file2.txt", "nested content".as_bytes(), 0o644);

        let mut builder = ImageFixture::builder(output_type)
            .subdir("/subdir")
            .tar_content(tar);

        if output_type != OutputType::Tar {
            builder = builder.partition_size("50M");
        }

        let image = builder.build();

        let mounted = image.mount();
        mounted.assert_file_content("file2.txt", "nested content");
        mounted.assert_file_not_exists("file1.txt");
        mounted.assert_file_not_exists("subdir/file2.txt");
    }

    #[test]
    fn test_extra_files(output_type in all_types()) {
        let temp_dir = TempDir::new().unwrap();
        let extra_file = temp_dir.path().join("extra.txt");
        fs::write(&extra_file, "extra content").unwrap();

        let mut tar = tar::Builder::new(Vec::new());
        append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);

        let mut builder = ImageFixture::builder(output_type)
            .extra_file(&format!("{}:/extra.txt:0644", extra_file.display()))
            .tar_content(tar);

        if output_type != OutputType::Tar {
            builder = builder.partition_size("50M");
        }

        let image = builder.build();

        let mounted = image.mount();
        mounted.assert_file_content("file1.txt", "test content");
        mounted.assert_file_content("extra.txt", "extra content");
    }

    #[test]
    fn test_large_files(output_type in all_types()) {
        let large_data = vec![0u8; 5 * 1024 * 1024];

        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(large_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "large.bin", large_data.as_slice()).unwrap();

        let image = ImageFixture::builder(output_type).partition_size_if_not_tar("50M")
            .tar_content(tar).build();

        let mounted = image.mount();
        mounted.assert_file_exists("large.bin");

        let file_size = fs::metadata(mounted.mount_point().join("large.bin")).unwrap().len();
        assert_eq!(file_size, large_data.len() as u64, "File size should match");
    }

    #[test]
    fn test_mtime_set(output_type in all_types()) {
        let mut tar = tar::Builder::new(Vec::new());

        append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);
        append_dir(&mut tar, "subdir", 0o755);
        append_file(&mut tar, "subdir/file2.txt", "nested content".as_bytes(), 0o644);

        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("50M")
            .tar_content(tar)
            .build();
        let mounted = image.mount();

        let expected_mtime = match output_type {
            OutputType::Fat32 | OutputType::Vfat => fat_min_time(),
            _ => SystemTime::UNIX_EPOCH,
        };

        for path in &["file1.txt", "subdir/file2.txt", "subdir"] {
            let metadata = fs::metadata(mounted.mount_point().join(path)).unwrap();
            assert_eq!(
                metadata.modified().unwrap(),
                expected_mtime,
                "{path} mtime should match",
            );
        }
    }

    #[test]
    fn test_symlinks(output_type in prop_oneof!(Just(OutputType::Ext4), Just(OutputType::Tar))) {
        let mut tar = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_size(11);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "target.txt", "test target".as_bytes()).unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        tar.append_link(&mut header, "link.txt", "target.txt").unwrap();

        let image = ImageFixture::builder(output_type).partition_size_if_not_tar("50M")
            .tar_content(tar).build();

        let mounted = image.mount();
        let link_path = mounted.mount_point().join("link.txt");
        assert!(link_path.exists(), "Symlink should exist");

        let metadata = fs::symlink_metadata(&link_path).unwrap();
        assert!(metadata.file_type().is_symlink(), "link.txt should be a symlink");

        let target = fs::read_link(&link_path).unwrap();
        assert_eq!(target, PathBuf::from("target.txt"), "Symlink target should be target.txt");
    }

    #[test]
    fn test_permissions_preserved(output_type in prop_oneof!(Just(OutputType::Ext4), Just(OutputType::Tar))) {
        let mut tar = tar::Builder::new(Vec::new());

        append_file(&mut tar, "script.sh", "script".as_bytes(), 0o755);
        append_file(&mut tar, "readonly.txt", "readonly".as_bytes(), 0o444);
        append_file(&mut tar, "writable.txt", "writable".as_bytes(), 0o644);

        let image = ImageFixture::builder(output_type).partition_size_if_not_tar("50M")
            .tar_content(tar).build();

        let mounted = image.mount();

        mounted.assert_permissions("script.sh", 0o755);
        mounted.assert_permissions("readonly.txt", 0o444);
        mounted.assert_permissions("writable.txt", 0o644);
    }

    #[test]
    fn test_ownership_preserved(output_type in prop_oneof!(Just(OutputType::Ext4), Just(OutputType::Tar))) {
        let mut tar = tar::Builder::new(Vec::new());

        append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);
        append_dir(&mut tar, "subdir", 0o755);
        append_file(&mut tar, "subdir/file2.txt", "nested content".as_bytes(), 0o644);

        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("50M")
            .tar_content(tar)
            .build();
        let mounted = image.mount();

        mounted.assert_ownership("file1.txt", 0, 0);
        mounted.assert_ownership("subdir/file2.txt", 0, 0);
        mounted.assert_ownership("subdir", 0, 0);
    }
}

// #[test]
// fn test_create_tar() -> Result<()> {
//     let mut tar = tar::Builder::new(Vec::new());
//
//     let mut header = tar::Header::new_gnu();
//     header.set_size(12);
//     header.set_mode(0o644);
//     header.set_cksum();
//     tar.append_data(&mut header, "file1.txt", "test content".as_bytes())?;
//
//     let mut header = tar::Header::new_gnu();
//     header.set_size(14);
//     header.set_mode(0o644);
//     header.set_cksum();
//     tar.append_data(&mut header, "subdir/file2.txt", "nested content".as_bytes())?;
//
//     let image = ImageFixture::builder(OutputType::Tar)
//         .tar_content(tar)
//         .build()?;
//
//     // Verify tar contents
//     let mut archive = tar::Archive::new(fs::File::open(image.path())?);
//     let entries: Vec<_> = archive
//         .entries()?
//         .filter_map(|e| e.ok())
//         .filter_map(|e| e.path().ok().map(|p| p.to_string_lossy().to_string()))
//         .collect();
//     assert_eq!(entries, vec!["file1.txt", "subdir/file2.txt"], "Tar contents should match");
//
//     Ok(())
// }

// #[test]
//
// fn test_empty_filesystem() -> Result<()> {
//     let image = ImageFixture::builder(OutputType::Ext4)
//         .partition_size("10M")
//         .build()?;
//     let mounted = image.mount()?;
//
//     // Should have lost+found for ext4
//     mounted.assert_dir_exists("lost+found")?;
//
//     // Count regular files (should be 0)
//     let file_count = walkdir::WalkDir::new(mounted.mount_point())
//         .into_iter()
//         .filter_map(|e| e.ok())
//         .filter(|e| e.file_type().is_file())
//         .count();
//     assert_eq!(file_count, 0, "Expected empty filesystem");
//
//     Ok(())
// }
//
// #[test]
//
// fn test_compressed_tar_output() -> Result<()> {
//     let temp_dir = TempDir::new()?;
//     let output = temp_dir.path().join("output.tar.zst");
//
//     let mut tar = tar::Builder::new(Vec::new());
//     let mut header = tar::Header::new_gnu();
//     header.set_size(12);
//     header.set_mode(0o644);
//     header.set_cksum();
//     tar.append_data(&mut header, "file1.txt", "test content".as_bytes())?;
//
//     let tar_data = tar.into_inner()?;
//     let tar_temp_dir = TempDir::new()?;
//     let input_tar = tar_temp_dir.path().join("input.tar");
//     fs::write(&input_tar, tar_data)?;
//
//     build_filesystem(Args {
//         output: output.clone(),
//         input: Some(input_tar),
//         output_type: OutputType::Tar,
//         partition_size: None,
//         label: None,
//         subdir: None,
//         file_contexts: None,
//         strip_paths: vec![],
//         extra_files: vec![],
//         mke2fs_path: get_mke2fs_path(),
//     })?;
//
//     drop(tar_temp_dir);
//     assert!(output.exists(), "Output file should exist");
//
//     // Verify it's a zstd compressed file by checking magic bytes
//     let mut file = fs::File::open(&output)?;
//     let mut magic = [0u8; 4];
//     file.read_exact(&mut magic)?;
//     drop(file);
//
//     // Zstandard magic number is 0x28, 0xB5, 0x2F, 0xFD
//     assert_eq!(
//         magic,
//         [0x28, 0xB5, 0x2F, 0xFD],
//         "Output should be Zstandard compressed"
//     );
//
//     // Extract and verify contents
//     let extracted = temp_dir.path().join("extracted.tar");
//     let zstd_output = std::process::Command::new("zstd")
//         .arg("-d")
//         .arg(&output)
//         .arg("-o")
//         .arg(&extracted)
//         .output()
//         .context("Failed to execute zstd")?;
//
//     assert!(zstd_output.status.success(), "zstd decompression failed");
//
//     // Verify tar contents
//     let tar_file = fs::File::open(&extracted)?;
//     let mut archive = tar::Archive::new(tar_file);
//     let entries: Vec<_> = archive
//         .entries()?
//         .filter_map(|e| e.ok())
//         .filter_map(|e| e.path().ok().map(|p| p.to_string_lossy().to_string()))
//         .collect();
//
//     assert!(
//         entries.iter().any(|e| e.contains("file1.txt")),
//         "Extracted tar should contain file1.txt"
//     );
//
//     Ok(())
// }
//
// #[test]
//
// fn test_invalid_partition_size() -> Result<()> {
//     let temp_dir = TempDir::new()?;
//
//     // Create input tar
//     let mut tar = tar::Builder::new(Vec::new());
//     let mut header = tar::Header::new_gnu();
//     header.set_size(12);
//     header.set_mode(0o644);
//     header.set_cksum();
//     tar.append_data(&mut header, "file1.txt", "test content".as_bytes())
//         ?;
//
//     let tar_data = tar.into_inner()?;
//     let input_tar = temp_dir.path().join("input.tar");
//     fs::write(&input_tar, tar_data)?;
//
//     let output = temp_dir.path().join("output.img");
//
//     let result = build_filesystem(Args {
//         output: output.clone(),
//         input: Some(input_tar),
//         output_type: OutputType::Ext4,
//         partition_size: None, // Missing required partition size
//         label: None,
//         subdir: None,
//         file_contexts: None,
//         strip_paths: vec![],
//         extra_files: vec![],
//         mke2fs_path: get_mke2fs_path(),
//     });
//
//     assert!(result.is_err(), "Should fail without partition size");
//
//     Ok(())
// }
