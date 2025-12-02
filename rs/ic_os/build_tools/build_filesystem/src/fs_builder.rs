use crate::path_converter::ImagePath;
use anyhow::Result;
use std::ffi::CString;
use std::io::Read;
use tar::Header;

/// Represents a filesystem entry with all its metadata
pub struct FileEntry<'a> {
    /// Path of the entry in the filesystem
    pub path: ImagePath,
    /// Tar header containing all metadata (mode, size, uid, gid, mtime, entry type, etc.)
    pub header: Header,
    /// Contents of the file (empty for directories)
    pub contents: &'a mut (dyn Read + 'a),
    /// SELinux security context (if specified)
    pub selinux_context: Option<CString>,
}

impl<'a> FileEntry<'a> {
    /// Create a new file entry
    pub fn new(path: ImagePath, header: Header, contents: &'a mut (dyn Read + 'a)) -> Self {
        Self {
            path,
            header,
            contents,
            selinux_context: None,
        }
    }

    /// Set the SELinux context for this entry
    pub fn with_selinux_context(mut self, context: Option<CString>) -> Self {
        self.selinux_context = context;
        self
    }
}

/// Trait for building different types of filesystems
pub trait FilesystemBuilder: Send {
    /// Append a file entry to the filesystem
    fn append_entry(&mut self, entry: FileEntry<'_>) -> Result<()>;

    /// Finalize the filesystem and flush any pending data
    fn finish(self: Box<Self>) -> Result<()>;

    /// Whether the filesystem needs a lost+found directory
    fn needs_lost_found(&self) -> bool;
}

