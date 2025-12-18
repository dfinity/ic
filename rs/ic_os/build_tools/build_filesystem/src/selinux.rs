use anyhow::Result;
use anyhow::{Context, ensure};
use std::ffi::CString;
use std::io::ErrorKind;
use std::os::raw::{c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Directory,
    RegularFile,
    Symlink,
}

unsafe impl Send for FileContexts {}

unsafe impl Sync for FileContexts {}

pub struct FileContexts {
    labeler: ::selinux::label::Labeler<::selinux::label::back_end::File>,
}

impl FileContexts {
    pub fn new(file_contexts_path: &Path) -> Result<Self> {
        ensure!(
            file_contexts_path.exists(),
            "File contexts file does not exist: {}",
            file_contexts_path.display()
        );

        // SELABEL_OPT_PATH constant for libselinux that allows specifying the file_contexts file
        // instead of the default policy file
        const SELABEL_OPT_PATH: c_int = 3;

        let path = CString::new(file_contexts_path.as_os_str().as_bytes())?;
        let options = [(SELABEL_OPT_PATH, path.as_ptr() as *const c_void)];

        // Use raw_format=true to avoid needing access to SELinux policy for translation
        let labeler =
            ::selinux::label::Labeler::<::selinux::label::back_end::File>::new(&options, true)
                .with_context(|| {
                    format!(
                        "Failed to create SELinux labeler with file_contexts: {}",
                        file_contexts_path.display()
                    )
                })?;

        Ok(Self { labeler })
    }

    pub fn find_context(&self, path: &Path, file_type: FileType) -> Result<Option<CString>> {
        ensure!(
            path.is_absolute(),
            "Path must be absolute: {}",
            path.display()
        );
        // File access modes from https://man7.org/linux/man-pages/man2/stat.2.html
        // S_IFDIR = 0o040000, S_IFREG = 0o100000, S_IFLNK = 0o120000
        let mode_value = match file_type {
            FileType::Directory => 0o040000,
            FileType::RegularFile => 0o100000,
            FileType::Symlink => 0o120000,
        };

        let file_mode = ::selinux::FileAccessMode::new(mode_value)
            .context("Failed to create FileAccessMode")?;

        match self.labeler.look_up_by_path(path, Some(file_mode)) {
            Ok(ctx) => Ok(ctx.to_c_string()?.map(|cstr| cstr.into_owned())),
            // If the path cannot be found in the selinux context file, return None
            Err(::selinux::errors::Error::IO { source, .. })
                if source.kind() == ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }
}
