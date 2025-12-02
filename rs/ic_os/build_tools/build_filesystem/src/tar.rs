use crate::fs_builder::{FileEntry, FilesystemBuilder};
use anyhow::Result;
use std::io::Write;
use tar::Builder;

/// Implementation of FilesystemBuilder for tar archives
pub struct TarBuilder<W: Write> {
    builder: Builder<W>,
}

impl<W: Write> TarBuilder<W> {
    pub fn new(builder: Builder<W>) -> Self {
        Self { builder }
    }

    pub fn into_inner(self) -> Builder<W> {
        self.builder
    }
}

impl<W: Write + Send> FilesystemBuilder for TarBuilder<W> {
    fn append_entry(&mut self, entry: FileEntry<'_>) -> Result<()> {
        let mut header = entry.header;

        if let Some(selinux_context) = &entry.selinux_context {
            self.builder.append_pax_extensions(vec![
                (
                    "SCHILY.xattr.security.selinux",
                    selinux_context.as_bytes_with_nul(),
                ),
                ("RHT.security.selinux", selinux_context.as_bytes_with_nul()),
            ])?;
        }

        self.builder
            .append_data(&mut header, entry.path.as_relative_path(), entry.contents)?;

        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<()> {
        self.builder.into_inner()?.flush()?;
        Ok(())
    }

    fn needs_lost_found(&self) -> bool {
        false
    }
}

