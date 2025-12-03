#![cfg(test)]

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use crate::{build_filesystem, Args, OutputType};

#[cfg(target_os = "linux")]
use anyhow::Context;

#[cfg(target_os = "linux")]
use ic_device::mount::{FileSystem, LoopDeviceMounter, MountOptions, Mounter};

use nix::unistd::ROOT;
#[cfg(target_os = "linux")]
use std::io::Read;

/// Ensure tests run with root privileges (required for mounting)
#[cfg(target_os = "linux")]
fn ensure_root() {
    unsafe {
        if nix::unistd::geteuid().is_root() {
            nix::unistd::seteuid(ROOT)
                .expect("Failed to set effective UID to root. Tests must be run with sudo.");
        }
    }
}

/// Get the mke2fs binary path from environment variable if available
fn get_mke2fs_path() -> Option<PathBuf> {
    std::env::var("MKE2FS_BIN").ok().map(PathBuf::from)
}

/// Test fixture for creating filesystem images and mounting them
#[allow(dead_code)]
struct ImageFixture {
    _temp_dir: TempDir,
    output_path: PathBuf,
}

#[allow(dead_code)]
impl ImageFixture {
    /// Create a new filesystem image with standard test content
    fn new(output_type: OutputType, partition_size: Option<&str>) -> Result<Self> {
        let temp_dir = TempDir::new()?;

        // Create input tar with standard content
        let content_dir = temp_dir.path().join("content");
        fs::create_dir_all(&content_dir.join("subdir"))?;
        fs::create_dir_all(&content_dir.join("emptydir"))?;
        fs::write(content_dir.join("file1.txt"), "test content")?;
        fs::write(content_dir.join("subdir/file2.txt"), "nested content")?;

        let input_tar = temp_dir.path().join("input.tar");
        Self::create_tar(&content_dir, &input_tar)?;

        // Create output image
        let output_path = Self::output_path_for_type(&temp_dir, &output_type);

        build_filesystem(Args {
            output: output_path.clone(),
            input: Some(input_tar),
            output_type,
            partition_size: partition_size.map(|s| s.parse()).transpose()?,
            label: None,
            subdir: None,
            file_contexts: None,
            strip_paths: vec![],
            extra_files: vec![],
            mke2fs_path: get_mke2fs_path(),
        })?;

        Ok(Self {
            _temp_dir: temp_dir,
            output_path,
        })
    }

    /// Create a custom filesystem image
    fn with_content<F>(
        output_type: OutputType,
        partition_size: Option<&str>,
        setup: F,
    ) -> Result<Self>
    where
        F: FnOnce(&Path) -> Result<()>,
    {
        let temp_dir = TempDir::new()?;

        // Create input tar with custom content
        let content_dir = temp_dir.path().join("content");
        fs::create_dir(&content_dir)?;
        setup(&content_dir)?;

        let input_tar = temp_dir.path().join("input.tar");
        Self::create_tar(&content_dir, &input_tar)?;

        // Create output image
        let output_path = Self::output_path_for_type(&temp_dir, &output_type);

        build_filesystem(Args {
            output: output_path.clone(),
            input: Some(input_tar),
            output_type,
            partition_size: partition_size.map(|s| s.parse()).transpose()?,
            label: None,
            subdir: None,
            file_contexts: None,
            strip_paths: vec![],
            extra_files: vec![],
            mke2fs_path: get_mke2fs_path(),
        })?;

        Ok(Self {
            _temp_dir: temp_dir,
            output_path,
        })
    }

    /// Create an empty filesystem
    fn empty(output_type: OutputType, partition_size: &str) -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let output_path = Self::output_path_for_type(&temp_dir, &output_type);

        build_filesystem(Args {
            output: output_path.clone(),
            input: None,
            output_type,
            partition_size: Some(partition_size.parse()?),
            label: None,
            subdir: None,
            file_contexts: None,
            strip_paths: vec![],
            extra_files: vec![],
            mke2fs_path: get_mke2fs_path(),
        })?;

        Ok(Self {
            _temp_dir: temp_dir,
            output_path,
        })
    }

    fn output_path_for_type(temp_dir: &TempDir, output_type: &OutputType) -> PathBuf {
        match output_type {
            OutputType::Tar => temp_dir.path().join("output.tar"),
            OutputType::Ext4 | OutputType::Vfat | OutputType::Fat32 => {
                temp_dir.path().join("output.img")
            }
        }
    }

    fn create_tar(source_dir: &Path, tar_path: &Path) -> Result<()> {
        let tar_file = fs::File::create(tar_path)?;
        let mut tar_builder = tar::Builder::new(tar_file);
        tar_builder.append_dir_all(".", source_dir)?;
        tar_builder.finish()?;
        Ok(())
    }

    fn path(&self) -> &Path {
        &self.output_path
    }

    /// Mount the image (Linux only)
    #[cfg(target_os = "linux")]
    async fn mount(&self, fs_type: FileSystem) -> Result<MountedImage> {
        MountedImage::mount(self.path(), fs_type).await
    }

    /// Extract and verify tar contents
    fn verify_tar_contents(&self) -> Result<Vec<String>> {
        let tar_file = fs::File::open(self.path())?;
        let mut archive = tar::Archive::new(tar_file);
        let mut entries = Vec::new();

        for entry in archive.entries()? {
            let entry = entry?;
            if let Ok(path) = entry.path() {
                entries.push(path.to_string_lossy().to_string());
            }
        }

        Ok(entries)
    }

    /// Extract tar.zst and return path to extracted tar
    #[cfg(target_os = "linux")]
    fn extract_zst(&self) -> Result<PathBuf> {
        use std::process::Command;

        let extracted = self._temp_dir.path().join("extracted.tar");

        let output = Command::new("zstd")
            .arg("-d")
            .arg(self.path())
            .arg("-o")
            .arg(&extracted)
            .output()
            .context("Failed to execute zstd")?;

        if !output.status.success() {
            anyhow::bail!("zstd decompression failed");
        }

        Ok(extracted)
    }
}

/// Helper to mount an image and verify contents
#[cfg(target_os = "linux")]
struct MountedImage {
    _mount: Box<dyn ic_device::mount::MountedPartition>,
}

#[cfg(target_os = "linux")]
impl MountedImage {
    async fn mount(image_path: &Path, fs_type: FileSystem) -> Result<Self> {
        ensure_root();
        let mount = LoopDeviceMounter
            .mount_range(
                image_path.to_path_buf(),
                0,
                0,
                MountOptions {
                    file_system: fs_type,
                },
            )
            .await?;
        Ok(Self { _mount: mount })
    }

    fn mount_point(&self) -> &Path {
        self._mount.mount_point()
    }

    /// Assert file exists with expected content
    fn assert_file_content(&self, path: &str, expected: &str) -> Result<()> {
        let file_path = self.mount_point().join(path);
        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        assert_eq!(content, expected, "File {} has wrong content", path);
        Ok(())
    }

    /// Assert file exists
    fn assert_file_exists(&self, path: &str) -> Result<()> {
        let file_path = self.mount_point().join(path);
        assert!(file_path.exists(), "File {} does not exist", path);
        Ok(())
    }

    /// Assert directory exists
    fn assert_dir_exists(&self, path: &str) -> Result<()> {
        let dir_path = self.mount_point().join(path);
        assert!(dir_path.is_dir(), "Directory {} does not exist", path);
        Ok(())
    }

    /// Assert file has specific permissions
    #[cfg(target_os = "linux")]
    fn assert_permissions(&self, path: &str, expected_mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let file_path = self.mount_point().join(path);
        let metadata = fs::metadata(&file_path)?;
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, expected_mode,
            "File {} has wrong permissions: {:o} (expected {:o})",
            path, mode, expected_mode
        );
        Ok(())
    }

    /// Assert file has specific ownership
    #[cfg(target_os = "linux")]
    fn assert_ownership(&self, path: &str, expected_uid: u32, expected_gid: u32) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let file_path = self.mount_point().join(path);
        let metadata = fs::metadata(&file_path)?;
        assert_eq!(metadata.uid(), expected_uid, "File {} has wrong uid", path);
        assert_eq!(metadata.gid(), expected_gid, "File {} has wrong gid", path);
        Ok(())
    }
}

#[test]
#[cfg(target_os = "linux")]
fn test_create_tar() -> Result<()> {
    let image = ImageFixture::new(OutputType::Tar, None)?;

    // Verify tar contents
    let entries = image.verify_tar_contents()?;
    assert!(!entries.is_empty(), "Tar file is empty");
    assert!(entries.iter().any(|e| e.contains("file1.txt")));
    assert!(entries.iter().any(|e| e.contains("file2.txt")));

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_create_ext4() -> Result<()> {
    let image = ImageFixture::new(OutputType::Ext4, Some("50M"))?;
    let mounted = image.mount(FileSystem::Ext4).await?;

    mounted.assert_file_content("file1.txt", "test content")?;
    mounted.assert_file_content("subdir/file2.txt", "nested content")?;
    mounted.assert_dir_exists("emptydir")?;
    mounted.assert_dir_exists("subdir")?;

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_create_vfat() -> Result<()> {
    let image = ImageFixture::new(OutputType::Vfat, Some("50M"))?;
    let mounted = image.mount(FileSystem::Vfat).await?;

    mounted.assert_file_content("file1.txt", "test content")?;
    mounted.assert_file_content("subdir/file2.txt", "nested content")?;

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_create_fat32_with_label() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create input tar
    let content_dir = temp_dir.path().join("content");
    fs::create_dir(&content_dir)?;
    fs::write(content_dir.join("file1.txt"), "test content")?;

    let input_tar = temp_dir.path().join("input.tar");
    ImageFixture::create_tar(&content_dir, &input_tar)?;

    let output = temp_dir.path().join("output.img");

    build_filesystem(Args {
        output: output.clone(),
        input: Some(input_tar),
        output_type: OutputType::Fat32,
        partition_size: Some("50M".parse()?),
        label: Some("TESTLABEL".to_string()),
        subdir: None,
        file_contexts: None,
        strip_paths: vec![],
        extra_files: vec![],
        mke2fs_path: get_mke2fs_path(),
    })?;

    // Verify label
    let output_label = std::process::Command::new("blkid")
        .arg("-s")
        .arg("LABEL")
        .arg("-o")
        .arg("value")
        .arg(&output)
        .output()?;
    let label = String::from_utf8_lossy(&output_label.stdout)
        .trim()
        .to_string();
    assert_eq!(label, "TESTLABEL");

    let mounted = MountedImage::mount(&output, FileSystem::Vfat).await?;
    mounted.assert_file_content("file1.txt", "test content")?;

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_subdir_extraction() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create input tar
    let content_dir = temp_dir.path().join("content");
    fs::create_dir_all(&content_dir.join("subdir"))?;
    fs::write(content_dir.join("file1.txt"), "test content")?;
    fs::write(content_dir.join("subdir/file2.txt"), "nested content")?;

    let input_tar = temp_dir.path().join("input.tar");
    ImageFixture::create_tar(&content_dir, &input_tar)?;

    let output = temp_dir.path().join("output.img");

    build_filesystem(Args {
        output: output.clone(),
        input: Some(input_tar),
        output_type: OutputType::Ext4,
        partition_size: Some("50M".parse()?),
        label: None,
        subdir: Some(PathBuf::from("/subdir")),
        file_contexts: None,
        strip_paths: vec![],
        extra_files: vec![],
    })?;

    let mounted = MountedImage::mount(&output, FileSystem::Ext4).await?;
    // Should have file2.txt from subdir
    mounted.assert_file_content("file2.txt", "nested content")?;
    // Should NOT have file1.txt from root
    assert!(!mounted.mount_point().join("file1.txt").exists());

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_extra_files() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create input tar
    let content_dir = temp_dir.path().join("content");
    fs::create_dir(&content_dir)?;
    fs::write(content_dir.join("file1.txt"), "test content")?;

    let input_tar = temp_dir.path().join("input.tar");
    ImageFixture::create_tar(&content_dir, &input_tar)?;

    // Create extra file
    let extra_file = temp_dir.path().join("extra_source.txt");
    fs::write(&extra_file, "extra content")?;

    let output = temp_dir.path().join("output.img");

    build_filesystem(Args {
        output: output.clone(),
        input: Some(input_tar),
        output_type: OutputType::Ext4,
        partition_size: Some("50M".parse()?),
        label: None,
        subdir: None,
        file_contexts: None,
        strip_paths: vec![],
        extra_files: vec![format!("{}:/extra.txt:0644", extra_file.display())],
    })?;

    let mounted = MountedImage::mount(&output, FileSystem::Ext4).await?;
    mounted.assert_file_content("extra.txt", "extra content")?;
    mounted.assert_file_content("file1.txt", "test content")?;

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_empty_filesystem() -> Result<()> {
    let image = ImageFixture::empty(OutputType::Ext4, "10M")?;
    let mounted = image.mount(FileSystem::Ext4).await?;

    // Should have lost+found for ext4
    mounted.assert_dir_exists("lost+found")?;

    // Count regular files (should be 0)
    let file_count = walkdir::WalkDir::new(mounted.mount_point())
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    assert_eq!(file_count, 0, "Expected empty filesystem");

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_large_file() -> Result<()> {
    let image = ImageFixture::with_content(OutputType::Ext4, Some("50M"), |dir| {
        // Create a 5MB file
        let large_file = dir.join("large.bin");
        let mut file = fs::File::create(&large_file)?;
        file.set_len(5 * 1024 * 1024)?;
        Ok(())
    })?;

    let mounted = image.mount(FileSystem::Ext4).await?;
    mounted.assert_file_exists("large.bin")?;

    let metadata = fs::metadata(mounted.mount_point().join("large.bin"))?;
    assert_eq!(metadata.len(), 5 * 1024 * 1024, "Large file has wrong size");

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_symlinks() -> Result<()> {
    let image = ImageFixture::with_content(OutputType::Ext4, Some("50M"), |dir| {
        fs::write(dir.join("target.txt"), "target")?;
        std::os::unix::fs::symlink("target.txt", dir.join("link.txt"))?;
        Ok(())
    })?;

    let mounted = image.mount(FileSystem::Ext4).await?;
    let link_path = mounted.mount_point().join("link.txt");
    assert!(link_path.exists(), "Symlink does not exist");

    let metadata = fs::symlink_metadata(&link_path)?;
    assert!(
        metadata.file_type().is_symlink(),
        "link.txt is not a symlink"
    );

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_mtime_set_to_zero() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let image = ImageFixture::new(OutputType::Ext4, Some("50M"))?;
    let mounted = image.mount(FileSystem::Ext4).await?;

    // Check file mtime
    let file_metadata = fs::metadata(mounted.mount_point().join("file1.txt"))?;
    assert_eq!(file_metadata.mtime(), 0, "file1.txt mtime should be 0");

    // Check nested file mtime
    let nested_metadata = fs::metadata(mounted.mount_point().join("subdir/file2.txt"))?;
    assert_eq!(
        nested_metadata.mtime(),
        0,
        "subdir/file2.txt mtime should be 0"
    );

    // Check directory mtime
    let dir_metadata = fs::metadata(mounted.mount_point().join("subdir"))?;
    assert_eq!(dir_metadata.mtime(), 0, "subdir mtime should be 0");

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_permissions_preserved() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let image = ImageFixture::with_content(OutputType::Ext4, Some("50M"), |dir| {
        let script = dir.join("script.sh");
        fs::write(&script, "#!/bin/bash\necho hello")?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))?;

        let readonly = dir.join("readonly.txt");
        fs::write(&readonly, "readonly")?;
        fs::set_permissions(&readonly, fs::Permissions::from_mode(0o444))?;

        let writable = dir.join("writable.txt");
        fs::write(&writable, "writable")?;
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o644))?;

        Ok(())
    })?;

    let mounted = image.mount(FileSystem::Ext4).await?;
    mounted.assert_permissions("script.sh", 0o755)?;
    mounted.assert_permissions("readonly.txt", 0o444)?;
    mounted.assert_permissions("writable.txt", 0o644)?;

    // Verify executable bit
    let script_metadata = fs::metadata(mounted.mount_point().join("script.sh"))?;
    assert!(
        script_metadata.permissions().mode() & 0o111 != 0,
        "script.sh should be executable"
    );

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_ownership_preserved() -> Result<()> {
    let image = ImageFixture::new(OutputType::Ext4, Some("50M"))?;
    let mounted = image.mount(FileSystem::Ext4).await?;

    // Files should be owned by root (uid=0, gid=0) when created by the tool
    mounted.assert_ownership("file1.txt", 0, 0)?;
    mounted.assert_ownership("subdir/file2.txt", 0, 0)?;

    // Check directory ownership
    mounted.assert_ownership("subdir", 0, 0)?;

    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_compressed_tar_output() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create input tar
    let content_dir = temp_dir.path().join("content");
    fs::create_dir(&content_dir)?;
    fs::write(content_dir.join("file1.txt"), "test content")?;

    let input_tar = temp_dir.path().join("input.tar");
    ImageFixture::create_tar(&content_dir, &input_tar)?;

    let output = temp_dir.path().join("output.tar.zst");

    build_filesystem(Args {
        output: output.clone(),
        input: Some(input_tar),
        output_type: OutputType::Tar,
        partition_size: None,
        label: None,
        subdir: None,
        file_contexts: None,
        strip_paths: vec![],
        extra_files: vec![],
    })?;

    assert!(output.exists());

    // Verify it's a zstd compressed file by checking magic bytes
    let mut file = fs::File::open(&output)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    drop(file);

    // Zstandard magic number is 0x28, 0xB5, 0x2F, 0xFD
    assert_eq!(
        magic,
        [0x28, 0xB5, 0x2F, 0xFD],
        "Output should be Zstandard compressed"
    );

    // Extract and verify contents
    let extracted = temp_dir.path().join("extracted.tar");
    let zstd_output = std::process::Command::new("zstd")
        .arg("-d")
        .arg(&output)
        .arg("-o")
        .arg(&extracted)
        .output()
        .context("Failed to execute zstd")?;

    if !zstd_output.status.success() {
        anyhow::bail!("zstd decompression failed");
    }

    // Verify tar contents
    let tar_file = fs::File::open(&extracted)?;
    let mut archive = tar::Archive::new(tar_file);
    let entries: Vec<_> = archive
        .entries()?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.path().ok().map(|p| p.to_string_lossy().to_string()))
        .collect();

    assert!(
        entries.iter().any(|e| e.contains("file1.txt")),
        "Extracted tar should contain file1.txt"
    );

    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn test_invalid_partition_size() {
    let temp_dir = TempDir::new().unwrap();

    // Create input tar
    let content_dir = temp_dir.path().join("content");
    fs::create_dir(&content_dir).unwrap();
    fs::write(content_dir.join("file1.txt"), "test content").unwrap();

    let input_tar = temp_dir.path().join("input.tar");
    ImageFixture::create_tar(&content_dir, &input_tar).unwrap();

    let output = temp_dir.path().join("output.img");

    let result = build_filesystem(Args {
        output: output.clone(),
        input: Some(input_tar),
        output_type: OutputType::Ext4,
        partition_size: None, // Missing required partition size
        label: None,
        subdir: None,
        file_contexts: None,
        strip_paths: vec![],
        extra_files: vec![],
        mke2fs_path: get_mke2fs_path(),
    });

    assert!(result.is_err(), "Should fail without partition size");
}
