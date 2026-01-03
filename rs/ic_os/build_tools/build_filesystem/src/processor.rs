use crate::ExtraFile;
use crate::fs_builder::{FileEntry, FilesystemBuilder};
use crate::path_converter::{ImagePath, PathConverter};
use crate::selinux::{FileContexts, FileType};
use anyhow::{Context, Result, bail};
use regex::RegexSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::{Archive, Header};

pub fn process_filesystem(
    input_tar_path: Option<&Path>,
    output_builder: &mut dyn FilesystemBuilder,
    subdir: Option<&Path>,
    strip_paths: &RegexSet,
    extra_files: &[ExtraFile],
    selinux_file_contexts: &Option<FileContexts>,
) -> Result<()> {
    let path_converter = PathConverter::new(subdir.map(PathBuf::from));
    add_root(output_builder, selinux_file_contexts, &path_converter)?;
    if output_builder.needs_lost_found() {
        add_lost_found(output_builder, &path_converter, selinux_file_contexts)?;
    }

    if let Some(input_tar_path) = input_tar_path {
        process_input_tar(
            input_tar_path,
            output_builder,
            &path_converter,
            selinux_file_contexts,
            strip_paths,
        )?;
    }

    process_extra_files(
        extra_files,
        output_builder,
        &path_converter,
        selinux_file_contexts,
    )?;

    Ok(())
}

fn process_input_tar(
    input_tar_path: &Path,
    output_builder: &mut dyn FilesystemBuilder,
    path_converter: &PathConverter,
    selinux_file_contexts: &Option<FileContexts>,
    strip_paths: &RegexSet,
) -> Result<()> {
    let mut input_tar = Archive::new(std::io::BufReader::new(
        File::open(input_tar_path)
            .with_context(|| format!("Failed to open input file {:?}", input_tar_path))?,
    ));

    for entry in input_tar.entries()? {
        let mut entry = entry?;
        let source_path = ImagePath::from(entry.path().context("Failed to read entry path")?);

        if !strip_paths.is_match(
            source_path
                .as_absolute_path()
                .to_str()
                .context("Failed to convert path to string")?,
        ) && let Some(target_path) = path_converter.source_to_target(&source_path)
        {
            if entry.header().entry_type().is_dir() {
                add_entry(
                    output_builder,
                    entry.header().clone(),
                    &target_path,
                    &mut std::io::empty(),
                    path_converter,
                    selinux_file_contexts,
                )?;
            } else {
                add_entry(
                    output_builder,
                    entry.header().clone(),
                    &target_path,
                    &mut entry,
                    path_converter,
                    selinux_file_contexts,
                )?;
            }
        }
    }

    Ok(())
}

fn process_extra_files(
    extra_files: &[ExtraFile],
    output_builder: &mut dyn FilesystemBuilder,
    path_converter: &PathConverter,
    selinux_file_contexts: &Option<FileContexts>,
) -> Result<()> {
    for extra_file in extra_files {
        let metadata = std::fs::metadata(&extra_file.source)
            .with_context(|| format!("Failed to read metadata for {:?}", extra_file.source))?;
        let mut header = Header::new_gnu();
        header.set_size(metadata.len());
        header.set_mode(extra_file.mode);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        add_entry(
            output_builder,
            header,
            &extra_file.target,
            &mut File::open(&extra_file.source)?,
            path_converter,
            selinux_file_contexts,
        )?;
    }
    Ok(())
}

fn add_root(
    output_builder: &mut dyn FilesystemBuilder,
    file_contexts: &Option<FileContexts>,
    path_converter: &PathConverter,
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_mode(0o755);
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Directory);
    header.set_cksum();
    add_entry(
        output_builder,
        header,
        &ImagePath::root(),
        &mut std::io::empty(),
        path_converter,
        file_contexts,
    )
}

fn add_lost_found(
    output_builder: &mut dyn FilesystemBuilder,
    path_converter: &PathConverter,
    file_contexts: &Option<FileContexts>,
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_mode(0o700);
    header.set_entry_type(tar::EntryType::Directory);
    header.set_cksum();
    add_entry(
        output_builder,
        header,
        &ImagePath::from("lost+found"),
        &mut std::io::empty(),
        path_converter,
        file_contexts,
    )
}

fn add_entry(
    output_builder: &mut dyn FilesystemBuilder,
    mut header: Header,
    target_path: &ImagePath,
    data: &mut dyn Read,
    path_converter: &PathConverter,
    selinux_file_contexts: &Option<FileContexts>,
) -> Result<()> {
    let source_path = path_converter.target_to_source(target_path);

    assert!(
        !source_path.as_absolute_path().ends_with("/")
            || source_path.as_absolute_path() == Path::new("/")
    );
    assert!(
        !source_path.as_relative_path().ends_with("/")
            || source_path.as_relative_path() == Path::new(".")
    );

    // Always set mtime to 0 for reproducibility
    header.set_mtime(0);
    header.set_cksum();

    let selinux_context = if let Some(contexts) = selinux_file_contexts {
        let file_type = match header.entry_type() {
            t if t.is_dir() => Some(FileType::Directory),
            t if t.is_symlink() => Some(FileType::Symlink),
            t if t.is_file() => Some(FileType::RegularFile),
            t if t.is_hard_link() => None,
            _ => bail!(
                "{} has unsupported entry type: {:?}",
                source_path.as_absolute_path().display(),
                header.entry_type()
            ),
        };
        if let Some(file_type) = file_type {
            contexts.find_context(source_path.as_absolute_path(), file_type)?
        } else {
            None
        }
    } else {
        None
    };

    let file_entry =
        FileEntry::new(target_path.clone(), header, data).with_selinux_context(selinux_context);

    output_builder.append_entry(file_entry)
}
