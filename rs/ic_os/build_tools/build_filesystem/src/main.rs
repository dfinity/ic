use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, ValueEnum};
use regex::RegexSet;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use tempfile::NamedTempFile;

mod ext4;
mod fat;
mod fs_builder;
mod integration_tests;
mod partition_size;
mod path_converter;
mod processor;
mod selinux;
mod tar;

use crate::partition_size::PartitionSize;
use crate::path_converter::ImagePath;
use ext4::Ext4Builder;
use fat::{FatBuilder, FatType};
use fs_builder::FilesystemBuilder;
use selinux::FileContexts;
use tar::TarBuilder;

#[derive(Parser, Debug)]
#[command(about = "Build filesystem images from input tar with transformations")]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct Args {
    /// Output file path
    #[arg(short = 'o', long)]
    pub(crate) output: PathBuf,

    /// Input tar file (optional, if not provided creates empty filesystem)
    #[arg(short = 'i', long)]
    pub(crate) input: Option<PathBuf>,

    /// Output type (tar, ext4, vfat, fat32)
    #[arg(short = 't', long, value_enum, default_value = "tar")]
    pub(crate) output_type: OutputType,

    /// Partition size (required for ext4, vfat, and fat32, e.g., "100M", "1G")
    #[arg(long)]
    pub(crate) partition_size: Option<PartitionSize>,

    /// Volume label (optional, for fat32 filesystems)
    #[arg(long)]
    pub(crate) label: Option<String>,

    /// Path to extract from input tar (limit to subdirectory)
    #[arg(short = 'p', long)]
    pub(crate) subdir: Option<PathBuf>,

    /// SELinux file_contexts file for setting security contexts
    #[arg(short = 'S', long)]
    pub(crate) file_contexts: Option<PathBuf>,

    /// Paths to remove from the tree
    #[arg(long = "strip-paths", num_args = 0..)]
    pub(crate) strip_paths: Vec<String>,

    /// Extra files to inject (format: source:target:mode)
    #[arg(long = "extra-files", num_args = 0..)]
    pub(crate) extra_files: Vec<ExtraFile>,

    /// Path to mke2fs binary (optional, defaults to system mke2fs)
    #[arg(long = "mke2fs")]
    pub(crate) mke2fs_path: Option<PathBuf>,
}

#[derive(Debug, Clone, ValueEnum, Eq, PartialEq)]
#[cfg_attr(test, derive(Copy))]
pub(crate) enum OutputType {
    Tar,
    Ext4,
    Vfat,
    Fat32,
}

/// Extra file to inject into the filesystem image
#[derive(Debug, Clone)]
pub(crate) struct ExtraFile {
    /// Source file path on the host filesystem
    pub(crate) source: PathBuf,
    /// Target path in the filesystem image
    pub(crate) target: ImagePath,
    /// File permissions mode (octal, e.g., 0o644)
    pub(crate) mode: u32,
}

impl FromStr for ExtraFile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            bail!("Invalid extra file format: {s}. Expected source:target:mode");
        }

        let source = PathBuf::from(parts[0]);
        let target = ImagePath::from(parts[1]);
        let mode = u32::from_str_radix(parts[2], 8)
            .with_context(|| format!("Invalid mode in extra file: {}", parts[2]))?;

        Ok(ExtraFile {
            source,
            target,
            mode,
        })
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    build_filesystem(args)
}

/// Main build_filesystem logic that can be called programmatically
pub(crate) fn build_filesystem(args: Args) -> Result<()> {
    let output_str = args.output.to_str().unwrap_or_default();

    if args.output_type == OutputType::Tar {
        let tar_extensions = [".tar", ".tar.zst", ".tzst"];
        ensure!(
            tar_extensions.iter().any(|ext| output_str.ends_with(ext)),
            "Output file for tar must have one of the following extensions: {}",
            tar_extensions.join(", ")
        );
        ensure!(
            args.label.is_none(),
            "Volume label is not allowed for tar output"
        );
        ensure!(
            args.partition_size.is_none(),
            "Partition size is not allowed for tar output"
        );
    } else {
        let extensions = [".img", ".img.zst"];
        ensure!(
            extensions.iter().any(|ext| output_str.ends_with(ext)),
            "Output file for raw image must have one of the following extensions: {}",
            extensions.join(", ")
        );
    }

    if !args.strip_paths.is_empty() && args.subdir.is_some() {
        // There is no real reason not to allow these options together. However, we need to
        // figure out if strip_paths should contain paths relative to subdir or paths relative to
        // the root of the input tar.
        bail!(
            "Cannot use --strip-paths and --subdir together, if you need it, please \
               implement it"
        );
    }

    // Validate input exists if provided
    if let Some(input) = &args.input {
        ensure!(input.exists(), "Input file does not exist: {input:?}");
    }

    let file_contexts = args
        .file_contexts
        .map(|path| FileContexts::new(&path))
        .transpose()?;

    let strip_paths = RegexSet::new(args.strip_paths.iter().map(|s| {
        assert!(s.starts_with('/'), "strip path must start with /");
        // RegexSet matches anywhere in the string, so we anchor it
        format!("^{s}$")
    }))?;

    let needs_compression = output_str.ends_with(".zst") || output_str.ends_with(".tzst");
    let _temp_path;
    // If compression is required, create a temporary file first, then compress it later
    let image_path: &Path = if needs_compression {
        _temp_path = NamedTempFile::new()?.into_temp_path();
        _temp_path.as_ref()
    } else {
        &args.output
    };

    let mut output_builder: Box<dyn FilesystemBuilder> = match args.output_type {
        OutputType::Tar => {
            let output_file = File::create(image_path)
                .with_context(|| format!("Failed to create output file {:?}", image_path))?;
            let tar_builder = ::tar::Builder::new(BufWriter::new(output_file));
            Box::new(TarBuilder::new(tar_builder))
        }
        OutputType::Ext4 => {
            let partition_size = args
                .partition_size
                .context("Partition size is required for ext4")?;
            Box::new(Ext4Builder::new(
                image_path,
                partition_size,
                args.label,
                args.mke2fs_path.clone(),
            )?)
        }
        OutputType::Vfat => {
            let partition_size = args
                .partition_size
                .context("Partition size is required for vfat")?;
            Box::new(FatBuilder::new(
                image_path,
                partition_size,
                FatType::Vfat,
                args.label,
            )?)
        }
        OutputType::Fat32 => {
            let partition_size = args
                .partition_size
                .context("Partition size is required for fat32")?;
            Box::new(FatBuilder::new(
                image_path,
                partition_size,
                FatType::Fat32,
                args.label,
            )?)
        }
    };

    processor::process_filesystem(
        args.input.as_deref(),
        output_builder.as_mut(),
        args.subdir.as_deref(),
        &strip_paths,
        &args.extra_files,
        &file_contexts,
    )?;

    output_builder.finish()?;

    if needs_compression {
        let output = Command::new("zstd")
            .args(["-T0", "--quiet", "--force", "-o"])
            .arg(&args.output)
            .arg(image_path)
            .output()
            .context("Failed to run zstd")?;
        ensure!(output.status.success(), "compression failed: {output:?}");
    }

    Ok(())
}
