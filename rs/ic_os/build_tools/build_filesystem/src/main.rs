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
    ensure!(
        output_str.ends_with(".tar")
            || output_str.ends_with(".tar.zst")
            || output_str.ends_with(".tzst")
            || output_str.ends_with(".img"),
        "Output file must have .tar, .tar.zst, .tzst, or .img extension: {}",
        args.output.display()
    );

    if args.output_type == OutputType::Tar {
        ensure!(
            output_str.ends_with(".tar")
                || output_str.ends_with(".tar.zst")
                || output_str.ends_with(".tzst"),
            "Output file for tar must have .tar, .tar.zst or .tzst extension: {}",
            args.output.display()
        );
        ensure!(
            args.label.is_none(),
            "Volume label is not allowed for tar output"
        );
        ensure!(
            args.partition_size.is_none(),
            "Partition size is not allowed for tar output"
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

    let needs_compression = if output_str.ends_with(".img") {
        // Output raw image
        false
    } else if args.output_type == OutputType::Tar && output_str.ends_with(".tar") {
        // Output built filesystem tar
        false
    } else {
        true
    };

    let file_contexts = args
        .file_contexts
        .map(|path| FileContexts::new(&path))
        .transpose()?;

    let strip_paths = RegexSet::new(args.strip_paths.iter().map(|s| {
        assert!(s.starts_with('/'), "strip path must start with /");
        // RegexSet matches anywhere in the string, so we anchor it
        format!("^{s}$")
    }))?;

    let _compressed_temp;
    // If compression is required, create a temporary file first, then compress it later
    let output_path: &Path = if needs_compression {
        // Create a temporary file and close it right away so it can be written by the image
        // creation process.
        _compressed_temp = NamedTempFile::new()?.into_temp_path();
        _compressed_temp.as_ref()
    } else {
        &args.output
    };

    let mut output_builder: Box<dyn FilesystemBuilder> = match args.output_type {
        OutputType::Tar => {
            let output_file = File::create(output_path)
                .with_context(|| format!("Failed to create output file {:?}", output_path))?;
            let tar_builder = ::tar::Builder::new(BufWriter::new(output_file));
            Box::new(TarBuilder::new(tar_builder))
        }
        OutputType::Ext4 => {
            let partition_size = args
                .partition_size
                .context("Partition size is required for ext4")?;
            Box::new(Ext4Builder::new(
                output_path,
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
                output_path,
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
                output_path,
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
        compress_output(&args.output, output_path, args.output_type)?;
    }

    Ok(())
}

fn compress_output(
    compressed_output_path: &PathBuf,
    output_path: &Path,
    output_type: OutputType,
) -> Result<()> {
    // If the output is a tar, we only need to compress it
    let output = if output_type == OutputType::Tar {
        Command::new("zstd")
            .arg("-q")
            .arg("--threads=0")
            .arg(output_path)
            .arg("-o")
            .arg(compressed_output_path)
            .output()
            .context("Failed to execute zstd")?
    } else {
        // If the output is an image, we tar + compress it
        Command::new("tar")
            .arg("-caf")
            .arg(compressed_output_path)
            .arg("--sparse")
            .arg("--transform")
            .arg("s|.*|partition.img|")
            .arg("-C")
            .arg(output_path.parent().unwrap())
            .arg(output_path.file_name().unwrap())
            .output()
            .context("Failed to execute tar")?
    };

    ensure!(output.status.success(), "compression failed: {output:?}");
    Ok(())
}
