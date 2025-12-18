#![cfg(test)]

use crate::fat::fat_min_time;
use crate::{Args, OutputType, build_filesystem};
use ic_device::mount::{FileSystem, LoopDeviceMounter, MountOptions, Mounter};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use tempfile::{NamedTempFile, TempDir, TempPath};

fn get_mke2fs_path() -> PathBuf {
    PathBuf::from(std::env::var("MKE2FS_BIN").unwrap())
}

/// Test fixture for creating filesystem images and mounting them
struct ImageFixture {
    /// The path where the image/tar is generated
    output_path: TempPath,
    output_type: OutputType,
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
    output_extension: &'static str,
}

impl ImageFixtureBuilder {
    fn new(output_type: OutputType) -> Self {
        let output_extension = match output_type {
            OutputType::Tar => "tar",
            OutputType::Ext4 => "img",
            OutputType::Vfat => "img",
            OutputType::Fat32 => "img",
        };
        Self {
            output_type,
            partition_size: None,
            label: None,
            subdir: None,
            file_contexts: None,
            strip_paths: Vec::new(),
            extra_files: Vec::new(),
            tar_builder: None,
            output_extension,
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
        let output_path = NamedTempFile::with_suffix(format!(".{}", self.output_extension))
            .unwrap()
            .into_temp_path();
        std::fs::remove_file(&output_path).unwrap();

        let input_tar = if let Some(builder) = self.tar_builder {
            let mut tar = NamedTempFile::new().unwrap();
            let tar_data = builder.into_inner().unwrap();
            tar.write_all(&tar_data).unwrap();
            Some(tar)
        } else {
            None
        };

        build_filesystem(Args {
            output: output_path.to_path_buf(),
            input: input_tar.as_ref().map(|t| t.path().to_path_buf()),
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

    /// Mount the image
    /// For tar files, this extracts the tar to a temporary directory
    /// For filesystem images, this mounts them using a loop device
    fn mount(&self) -> MountedImage {
        match self.output_type {
            OutputType::Tar => MountedImage::extract_tar(self.path()),
            _ => MountedImage::mount_loop(self.path(), self.filesystem_type()),
        }
    }

    /// Extract partition.img from the tar file and mount it
    fn mount_from_tar(&self) -> MountedImage {
        let temp_dir = TempDir::new().unwrap();
        let partition_img = temp_dir.path().join("partition.img");

        let output = Command::new("tar")
            .arg("-xaf")
            .arg(self.path())
            .arg("-C")
            .arg(temp_dir.path())
            .output()
            .unwrap();

        assert!(output.status.success(), "tar extraction failed");
        assert!(partition_img.exists(), "partition.img not found in tar");

        let named_temp = tempfile::NamedTempFile::new().unwrap();
        fs::copy(&partition_img, named_temp.path()).unwrap();

        MountedImage::mount_loop_with_temp(named_temp, self.filesystem_type())
    }
}

/// Helper to mount an image and verify contents
/// For tar files, this extracts to a temp directory
/// For filesystem images, this mounts using a loop device
enum MountedImage {
    // A file mounted using a loop device
    LoopMounted {
        mount: Box<dyn ic_device::mount::MountedPartition>,
    },
    // A file that was extracted from a tar and then mounted using a loop device
    LoopMountedFromTemp {
        mount: Box<dyn ic_device::mount::MountedPartition>,
        // We keep the extracted partition.img alive
        _extracted_partition_img: tempfile::NamedTempFile,
    },
    // A tar file that was extracted to a temp directory
    ExtractedTar {
        extracted_tar_dir: TempDir,
    },
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

        MountedImage::LoopMounted { mount }
    }

    /// Mount a filesystem image using a loop device, keeping the extracted partition image alive
    fn mount_loop_with_temp(
        extracted_partition_img: tempfile::NamedTempFile,
        fs_type: FileSystem,
    ) -> Self {
        let image_path = extracted_partition_img.path();

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

        MountedImage::LoopMountedFromTemp {
            mount,
            _extracted_partition_img: extracted_partition_img,
        }
    }

    /// Extract a tar file to a temporary directory
    fn extract_tar(tar_path: &Path) -> Self {
        use std::process::Command;

        let temp_dir = TempDir::new().unwrap();

        let output = Command::new("tar")
            .arg("-xaf")
            .arg(tar_path)
            .arg("--selinux")
            .arg("--same-owner")
            .arg("-C")
            .arg(temp_dir.path())
            .output()
            .unwrap();

        assert!(output.status.success(), "tar extraction failed");

        MountedImage::ExtractedTar {
            extracted_tar_dir: temp_dir,
        }
    }

    fn mount_point(&self) -> &Path {
        match self {
            MountedImage::LoopMounted { mount } => mount.mount_point(),
            MountedImage::LoopMountedFromTemp { mount, .. } => mount.mount_point(),
            MountedImage::ExtractedTar {
                extracted_tar_dir: temp_dir,
            } => temp_dir.path(),
        }
    }

    /// Assert file exists with expected content
    fn assert_file_content(&self, path: &str, expected: &str) {
        let file_path = self.mount_point().join(path);
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, expected, "File {} has wrong content", path);
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

fn all_types() -> [OutputType; 4] {
    [
        OutputType::Tar,
        OutputType::Ext4,
        OutputType::Vfat,
        OutputType::Fat32,
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

fn simple_tar() -> tar::Builder<Vec<u8>> {
    let mut tar = tar::Builder::new(Vec::new());
    append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);
    tar
}

fn simple_tar_with_subdir() -> tar::Builder<Vec<u8>> {
    let mut tar = tar::Builder::new(Vec::new());
    append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);
    append_dir(&mut tar, "subdir", 0o755);
    append_file(
        &mut tar,
        "subdir/file2.txt",
        "nested content".as_bytes(),
        0o644,
    );
    tar
}

fn simple_tar_with_empty_dir() -> tar::Builder<Vec<u8>> {
    let mut tar = simple_tar_with_subdir();
    append_dir(&mut tar, "emptydir", 0o755);
    tar
}

#[test]
fn test_basic_files_and_dirs() {
    for output_type in all_types() {
        println!("Testing output type: {:?}", output_type);
        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("4M")
            .tar_content(simple_tar_with_empty_dir())
            .build();

        let mounted = image.mount();

        mounted.assert_file_content("file1.txt", "test content");
        mounted.assert_file_content("subdir/file2.txt", "nested content");
        mounted.assert_dir_exists("emptydir");
        mounted.assert_dir_exists("subdir");
    }
}

#[test]
fn test_label() {
    for output_type in [OutputType::Vfat, OutputType::Fat32, OutputType::Ext4] {
        println!("Testing output type: {:?}", output_type);
        let label = format!("LBL{output_type:?}");
        let image = ImageFixture::builder(output_type)
            .partition_size("4M")
            .label(&label)
            .tar_content(simple_tar())
            .build();

        let mounted = image.mount();
        mounted.assert_file_content("file1.txt", "test content");

        assert!(
            (0..20).any(|_| {
                sleep(Duration::from_millis(100));
                Path::new(&format!("/dev/disk/by-label/{label}")).exists()
            }),
            "Label {} not found after 2 seconds",
            label
        );
    }
}

#[test]
fn test_subdir_extraction() {
    for output_type in all_types() {
        println!("Testing output type: {:?}", output_type);
        let mut tar = tar::Builder::new(Vec::new());

        append_file(&mut tar, "file1.txt", "test content".as_bytes(), 0o644);
        append_file(
            &mut tar,
            "subdir/file2.txt",
            "nested content".as_bytes(),
            0o644,
        );

        let builder = ImageFixture::builder(output_type)
            .subdir("/subdir")
            .tar_content(tar)
            .partition_size_if_not_tar("4M");

        let image = builder.build();

        let mounted = image.mount();
        mounted.assert_file_content("file2.txt", "nested content");
        mounted.assert_file_not_exists("file1.txt");
        mounted.assert_file_not_exists("subdir/file2.txt");
    }
}

#[test]
fn test_strip_paths() {
    for output_type in all_types() {
        println!("Testing output type: {:?}", output_type);
        let mut tar = tar::Builder::new(Vec::new());
        append_file(&mut tar, "keep1.txt", "keep this".as_bytes(), 0o644);
        append_file(&mut tar, "remove1.txt", "remove this".as_bytes(), 0o644);
        append_dir(&mut tar, "keepdir", 0o755);
        append_file(
            &mut tar,
            "keepdir/keep2.txt",
            "keep nested".as_bytes(),
            0o644,
        );
        append_file(
            &mut tar,
            "keepdir/remove2.txt",
            "remove nested".as_bytes(),
            0o644,
        );
        append_dir(&mut tar, "removedir", 0o755);
        append_file(
            &mut tar,
            "removedir/file.txt",
            "remove entire dir".as_bytes(),
            0o644,
        );
        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("4M")
            .strip_path("/remove1.txt")
            .strip_path("/keepdir/remove2.txt")
            .strip_path("/removedir/.*")
            .tar_content(tar)
            .build();

        let mounted = image.mount();

        mounted.assert_file_content("keep1.txt", "keep this");
        mounted.assert_file_content("keepdir/keep2.txt", "keep nested");
        mounted.assert_file_not_exists("remove1.txt");
        mounted.assert_file_not_exists("keepdir/remove2.txt");
        mounted.assert_file_not_exists("removedir/file.txt");
        mounted.assert_dir_exists("removedir");
    }
}

#[test]
fn test_extra_files() {
    for output_type in all_types() {
        println!("Testing output type: {:?}", output_type);
        let temp_dir = TempDir::new().unwrap();
        let extra_file = temp_dir.path().join("extra.txt");
        fs::write(&extra_file, "extra content").unwrap();

        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("4M")
            .extra_file(&format!("{}:/extra.txt:0644", extra_file.display()))
            .tar_content(simple_tar())
            .build();

        let mounted = image.mount();
        mounted.assert_file_content("file1.txt", "test content");
        mounted.assert_file_content("extra.txt", "extra content");
    }
}

#[test]
fn test_mtime_set() {
    for output_type in all_types() {
        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("4M")
            .tar_content(simple_tar_with_subdir())
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
}

#[test]
fn test_symlinks() {
    for output_type in [OutputType::Ext4, OutputType::Tar] {
        println!("Testing output type: {:?}", output_type);
        let mut tar = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_size(11);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "target.txt", "test target".as_bytes())
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        tar.append_link(&mut header, "link.txt", "target.txt")
            .unwrap();

        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("4M")
            .tar_content(tar)
            .build();

        let mounted = image.mount();
        let link_path = mounted.mount_point().join("link.txt");
        assert!(link_path.exists(), "Symlink should exist");

        let metadata = fs::symlink_metadata(&link_path).unwrap();
        assert!(
            metadata.file_type().is_symlink(),
            "link.txt should be a symlink"
        );

        let target = fs::read_link(&link_path).unwrap();
        assert_eq!(
            target,
            PathBuf::from("target.txt"),
            "Symlink target should be target.txt"
        );
    }
}

#[test]
fn test_permissions_preserved() {
    for output_type in [OutputType::Ext4, OutputType::Tar] {
        println!("Testing output type: {:?}", output_type);
        let mut tar = tar::Builder::new(Vec::new());

        append_file(&mut tar, "script.sh", "script".as_bytes(), 0o755);
        append_file(&mut tar, "readonly.txt", "readonly".as_bytes(), 0o444);
        append_file(&mut tar, "writable.txt", "writable".as_bytes(), 0o644);

        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("4M")
            .tar_content(tar)
            .build();

        let mounted = image.mount();

        mounted.assert_permissions("script.sh", 0o755);
        mounted.assert_permissions("readonly.txt", 0o444);
        mounted.assert_permissions("writable.txt", 0o644);
    }
}

#[test]
fn test_ownership_preserved() {
    for output_type in [OutputType::Ext4, OutputType::Tar] {
        println!("Testing output type: {:?}", output_type);
        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("4M")
            .tar_content(simple_tar_with_subdir())
            .build();
        let mounted = image.mount();

        mounted.assert_ownership("file1.txt", 0, 0);
        mounted.assert_ownership("subdir/file2.txt", 0, 0);
        mounted.assert_ownership("subdir", 0, 0);
    }
}

#[test]
fn test_selinux_labels() {
    for output_type in [OutputType::Ext4, OutputType::Tar] {
        println!("Testing output type: {:?}", output_type);
        let temp_dir = TempDir::new().unwrap();
        let file_contexts = temp_dir.path().join("file_contexts");

        fs::write(
            &file_contexts,
            "\
             /                 system_u:object_r:root_t:s0\n\
             /file1\\.txt      system_u:object_r:user_home_t:s0\n\
             /lost\\+found       system_u:object_r:lost_found_t:s0\n\
             /subdir(/.*)?     system_u:object_r:var_t:s0\n",
        )
        .unwrap();

        let image = ImageFixture::builder(output_type)
            .partition_size_if_not_tar("4M")
            .file_contexts(file_contexts)
            .tar_content(simple_tar_with_subdir())
            .build();
        let mounted = image.mount();

        assert_eq!(
            xattr::get(mounted.mount_point().join("file1.txt"), "security.selinux")
                .unwrap()
                .unwrap(),
            b"system_u:object_r:user_home_t:s0\0"
        );

        assert_eq!(
            xattr::get(mounted.mount_point().join("subdir"), "security.selinux")
                .unwrap()
                .unwrap(),
            b"system_u:object_r:var_t:s0\0"
        );

        assert_eq!(
            xattr::get(
                mounted.mount_point().join("subdir/file2.txt"),
                "security.selinux"
            )
            .unwrap()
            .unwrap(),
            b"system_u:object_r:var_t:s0\0"
        );

        assert_eq!(
            xattr::get(mounted.mount_point(), "security.selinux")
                .unwrap()
                .unwrap(),
            b"system_u:object_r:root_t:s0\0"
        );

        // lost+found is only created for ext4
        if output_type == OutputType::Ext4 {
            assert_eq!(
                xattr::get(mounted.mount_point().join("lost+found"), "security.selinux")
                    .unwrap()
                    .unwrap(),
                b"system_u:object_r:lost_found_t:s0\0"
            );
        }
    }
}

#[test]
fn test_zst_compressed_tar() {
    let mut builder = ImageFixture::builder(OutputType::Tar).tar_content(simple_tar());
    builder.output_extension = "tar.zst";

    let image = builder.build();
    let mounted = image.mount();

    mounted.assert_file_content("file1.txt", "test content");
}

#[test]
fn test_zst_compressed_images() {
    for output_type in [OutputType::Ext4, OutputType::Vfat, OutputType::Fat32] {
        let mut builder = ImageFixture::builder(output_type)
            .partition_size("4M")
            .tar_content(simple_tar());
        builder.output_extension = "tar.zst";

        let image = builder.build();
        let mounted = image.mount_from_tar();

        mounted.assert_file_content("file1.txt", "test content");
    }
}

#[test]
#[should_panic(expected = "Partition size is required")]
fn test_invalid_partition_size() {
    ImageFixture::builder(OutputType::Ext4)
        .tar_content(simple_tar())
        .build();
}
