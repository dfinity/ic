//! Assembles the merged state of a subnet merge.

use ic_protobuf::state::system_metadata::v1 as pb_metadata;
use ic_state_layout::{CANISTER_STATES_DIR, CheckpointLayout, SNAPSHOTS_DIR, WriteOnly};
use ic_types::Height;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// A `CheckpointLayout` has to be given a height, but the merge only asks it for
/// the paths of files inside the checkpoint, and those do not depend on one.
const HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED: Height = Height::new(0);

/// Assembles the checkpoint at `output` from the checkpoints at `base` and
/// `source`: it holds everything of `base`, with the canisters and canister
/// snapshots of `source` added to those of `base`, and is marked as the product
/// of a subnet merge.
///
/// Only the canisters and their snapshots are taken over from `source`.
/// Everything else (system metadata, subnet queues, ingress history, ...) is
/// `base`'s.
///
/// File contents are hard linked rather than copied, so this is cheap no matter
/// how large the two states are. That makes `output` share the storage of
/// `base` and `source`, which is sound because checkpoints are immutable.
pub fn do_merge(base: PathBuf, source: PathBuf, output: PathBuf) -> Result<(), String> {
    for (path, name) in [(&base, "base"), (&source, "source")] {
        if !path.is_dir() {
            return Err(format!(
                "the {name} checkpoint {} is not a directory",
                path.display()
            ));
        }
    }
    if output.exists() {
        return Err(format!("{} already exists", output.display()));
    }
    // An output under one of the inputs would be linked into itself, as the
    // linking creates it before listing the input it reads. Resolve the paths
    // first, as either side may reach the same directory through a link or a
    // `..`.
    let resolved_output = resolve(&output)?;
    for (input, name) in [(&base, "base"), (&source, "source")] {
        if resolved_output.starts_with(resolve(input)?) {
            return Err(format!(
                "the output {} is nested under the {name} checkpoint {}",
                output.display(),
                input.display()
            ));
        }
    }
    // The canisters of the two subnets are disjoint, as the source subnet hosts
    // the canister ID ranges that the merge reassigns to the destination subnet.
    for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
        if let Some(name) = common_entry(&base.join(dir), &source.join(dir))? {
            return Err(format!(
                "{dir} holds {name} in both {} and {}",
                base.display(),
                source.display()
            ));
        }
    }

    // Assemble next to the output and rename when done, so that a merge that
    // fails halfway leaves no directory where a checkpoint is expected. One that
    // is interrupted outright leaves the staging directory behind, which is why
    // it is not silently reused: whoever cleans it up should know it is there.
    let staging = staging_path(&output)?;
    if let Some(parent) = staging.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    // Creating the staging directory is what claims it, rather than a check that
    // it is free: the check would let two merges of the same output both proceed
    // into it, and the one that failed first would clean up while the other was
    // still assembling. Creating it is a single step that only one of them can
    // win, and the cleanup below is then this merge's to do.
    fs::create_dir(&staging).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{} exists, presumably left behind by an interrupted merge; remove it to retry",
                staging.display()
            )
        } else {
            format!("failed to create {}: {err}", staging.display())
        }
    })?;

    let mut renamed = false;
    let result = (|| -> Result<(), String> {
        assemble(&base, &source, &staging)?;

        fs::rename(&staging, &output).map_err(|err| {
            format!(
                "failed to move {} to {}: {err}",
                staging.display(),
                output.display()
            )
        })?;
        renamed = true;

        // A rename is not durable until the directory it happened in is synced,
        // so the checkpoint could otherwise be back at the staging path after a
        // crash. Through the resolved path: the parent of a bare relative one is
        // the empty path, which opens nothing.
        let parent = resolved_output
            .parent()
            .expect("a resolved path is absolute, so it has a parent");
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|err| format!("failed to sync {}: {err}", parent.display()))?;

        Ok(())
    })();
    if result.is_err() {
        // Whichever of the two the work is sitting in: a merge that reports a
        // failure must not leave a checkpoint behind, not even a complete one
        // whose durability is all that could not be established. The original
        // error is what the caller needs to see, so a failure to clean up must
        // not replace it.
        let _ = fs::remove_dir_all(if renamed { &output } else { &staging });
    }

    result
}

/// Assembles the merged checkpoint at `staging`, which must not exist.
fn assemble(base: &Path, source: &Path, staging: &Path) -> Result<(), String> {
    link_tree(base, staging)?;

    for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
        let source_dir = source.join(dir);
        if source_dir.exists() {
            link_tree(&source_dir, &staging.join(dir))?;
        }
    }

    let layout = CheckpointLayout::<WriteOnly>::new_untracked(
        staging.to_path_buf(),
        HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED,
    )
    .map_err(|err| format!("failed to create the checkpoint layout: {err:?}"))?;
    layout
        .subnet_merged_marker()
        .serialize(pb_metadata::SubnetMerged { merged: true })
        .map_err(|err| format!("failed to write the subnet merged marker: {err:?}"))?;

    // The files of a checkpoint are read-only, and the ones linked in already
    // are, being the very files of `base` and `source`; the marker written above
    // is not. Mark and sync as the state manager does before a directory it
    // assembled becomes a checkpoint. Directories stay writable, as they are in a
    // checkpoint the state manager wrote: only its files are marked.
    layout
        .mark_files_readonly_and_sync(/* thread_pool= */ None, /* perform_sync= */ true)
        .map_err(|err| format!("failed to mark the merged checkpoint read-only: {err:?}"))?;

    Ok(())
}

/// The directory the merged checkpoint is assembled in: a sibling of `output`,
/// so that the two are on the same file system and the hard links and the rename
/// both work.
///
/// The name is not one a checkpoint can have -- checkpoint directories are named
/// after a height in hexadecimal -- so the staging directory is recognizable as
/// what it is for as long as it exists.
fn staging_path(output: &Path) -> Result<PathBuf, String> {
    let name = output
        .file_name()
        .ok_or_else(|| format!("the output {} has no file name", output.display()))?;
    let mut staging = name.to_os_string();
    staging.push(".merging");
    Ok(output.with_file_name(staging))
}

/// Replicates the directory tree rooted at `from` under `to`, hard linking every
/// file. Directories that already exist under `to` are reused, so a tree can be
/// overlaid onto another one.
///
/// The directories are created writable, so that a subsequent call can overlay
/// onto them.
fn link_tree(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|err| format!("failed to create {}: {err}", to.display()))?;

    for entry in read_dir(from)? {
        let name = entry.file_name();
        let from = entry.path();
        let to = to.join(&name);

        let file_type = entry
            .file_type()
            .map_err(|err| format!("failed to stat {}: {err}", from.display()))?;
        if file_type.is_dir() {
            link_tree(&from, &to)?;
        } else {
            fs::hard_link(&from, &to).map_err(|err| {
                format!(
                    "failed to link {} to {}: {err}",
                    from.display(),
                    to.display()
                )
            })?;
        }
    }

    Ok(())
}

/// Resolves `path` to an absolute path with links and `..` components taken out.
///
/// `canonicalize` needs the path to exist, which the output does not, so the
/// deepest ancestor that does exist is resolved and the rest is appended. That is
/// enough for the nesting check: what an existing directory is nested under does
/// not change by appending to it.
fn resolve(path: &Path) -> Result<PathBuf, String> {
    // Absolute first: the ancestors of a bare relative path run out before
    // reaching the directory it is relative to, which is the one that exists.
    let absolute = std::path::absolute(path)
        .map_err(|err| format!("failed to resolve {}: {err}", path.display()))?;

    let mut suffix = PathBuf::new();
    let mut existing = absolute.as_path();
    loop {
        if existing.exists() {
            return Ok(existing
                .canonicalize()
                .map_err(|err| format!("failed to resolve {}: {err}", existing.display()))?
                .join(&suffix));
        }
        let name = existing.file_name().ok_or_else(|| {
            format!(
                "{} has no ancestor that exists, so it cannot be created",
                path.display()
            )
        })?;
        suffix = PathBuf::from(name).join(&suffix);
        existing = existing
            .parent()
            .expect("a path with a file name has a parent");
    }
}

/// Returns the name of an entry that both directories hold, if any. A directory
/// that does not exist holds nothing.
fn common_entry(left: &Path, right: &Path) -> Result<Option<String>, String> {
    let names = |dir: &Path| -> Result<BTreeSet<String>, String> {
        if !dir.exists() {
            return Ok(BTreeSet::new());
        }
        Ok(read_dir(dir)?
            .into_iter()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect())
    };

    let left = names(left)?;
    Ok(names(right)?.intersection(&left).next().cloned())
}

/// The entries of `dir`, with the I/O errors of both the listing and the entries
/// themselves resolved.
fn read_dir(dir: &Path) -> Result<Vec<fs::DirEntry>, String> {
    fs::read_dir(dir)
        .map_err(|err| format!("failed to read {}: {err}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("failed to read an entry of {}: {err}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_state_layout::{
        CANISTER_FILE, CompleteCheckpointLayout, SNAPSHOT_FILE, SUBNET_MERGED_FILE,
        SYSTEM_METADATA_FILE,
    };
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    /// Creates a checkpoint-shaped directory under `root`, holding a
    /// `system_metadata.pbuf`, a canister directory per entry of `canisters`,
    /// and one snapshot of each of those canisters.
    fn checkpoint(root: &Path, name: &str, canisters: &[&str]) -> PathBuf {
        let checkpoint = root.join(name);
        fs::create_dir_all(&checkpoint).unwrap();
        fs::write(checkpoint.join(SYSTEM_METADATA_FILE), name).unwrap();
        for canister in canisters {
            let canister_dir = checkpoint.join(CANISTER_STATES_DIR).join(canister);
            fs::create_dir_all(&canister_dir).unwrap();
            fs::write(canister_dir.join(CANISTER_FILE), *canister).unwrap();

            let snapshot_dir = snapshot_dir(&checkpoint, canister);
            fs::create_dir_all(&snapshot_dir).unwrap();
            fs::write(snapshot_dir.join(SNAPSHOT_FILE), *canister).unwrap();
        }
        checkpoint
    }

    /// The directory of `canister`'s snapshot within `checkpoint`. Snapshots sit
    /// one level deeper than canisters -- `snapshots/<canister>/<snapshot>` --
    /// which is what makes them the deepest thing the merge has to link.
    fn snapshot_dir(checkpoint: &Path, canister: &str) -> PathBuf {
        checkpoint
            .join(SNAPSHOTS_DIR)
            .join(canister)
            .join(format!("{canister}_snapshot"))
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = read_dir(dir)
            .unwrap()
            .into_iter()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn merge_unions_canisters_and_snapshots() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1", "c2"]);
        let source = checkpoint(tmp.path(), "source", &["c3"]);
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap();

        for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
            assert_eq!(entries(&output.join(dir)), ["c1", "c2", "c3"], "{dir}");
        }
        // One canister from either input, down to the snapshot itself.
        for canister in ["c2", "c3"] {
            let snapshot = snapshot_dir(&output, canister).join(SNAPSHOT_FILE);
            assert_eq!(fs::read_to_string(&snapshot).unwrap(), canister);
        }
    }

    #[test]
    fn merge_keeps_everything_else_from_base() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap();

        assert_eq!(
            fs::read_to_string(output.join(SYSTEM_METADATA_FILE)).unwrap(),
            "base"
        );
    }

    #[test]
    fn merge_hard_links_file_contents() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = tmp.path().join("merged");

        do_merge(base.clone(), source.clone(), output.clone()).unwrap();

        let inode = |path: PathBuf| fs::metadata(path).unwrap().ino();
        let canister = |root: &Path, canister: &str| {
            root.join(CANISTER_STATES_DIR)
                .join(canister)
                .join(CANISTER_FILE)
        };
        assert_eq!(
            inode(canister(&output, "c1")),
            inode(canister(&base, "c1")),
            "the canister of the base checkpoint is not hard linked"
        );
        assert_eq!(
            inode(canister(&output, "c2")),
            inode(canister(&source, "c2")),
            "the canister of the source checkpoint is not hard linked"
        );
    }

    #[test]
    fn merge_sets_the_subnet_merged_marker() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap();

        let layout = CompleteCheckpointLayout::new_untracked(
            output,
            HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED,
        )
        .unwrap();
        assert!(layout.subnet_merged_marker().deserialize().unwrap().merged);
    }

    #[test]
    fn merge_makes_the_files_read_only() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap();

        // The marker is the one file the merge writes itself, so it is the one
        // that is not already read-only by virtue of being a link into an input.
        let marker = output.join(SUBNET_MERGED_FILE);
        assert!(
            fs::metadata(&marker).unwrap().permissions().readonly(),
            "the subnet merged marker is writable",
        );
        for file in [
            output
                .join(CANISTER_STATES_DIR)
                .join("c1")
                .join(CANISTER_FILE),
            snapshot_dir(&output, "c1").join(SNAPSHOT_FILE),
        ] {
            assert!(
                fs::metadata(&file).unwrap().permissions().readonly(),
                "{} is writable",
                file.display(),
            );
        }
        // Directories stay writable, as they are in a checkpoint the state
        // manager wrote: only the files are marked.
        assert!(
            !fs::metadata(output.join(CANISTER_STATES_DIR))
                .unwrap()
                .permissions()
                .readonly(),
            "the canister states directory is read-only",
        );
    }

    #[test]
    fn merge_refuses_an_output_nested_under_an_input() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);

        // Directly under an input, under a directory of one, and reached through
        // a `..` that lands back inside one.
        for output in [
            base.join("merged"),
            base.join(CANISTER_STATES_DIR).join("merged"),
            source.join("merged"),
            tmp.path()
                .join("base")
                .join("..")
                .join("base")
                .join("merged"),
        ] {
            let err = do_merge(base.clone(), source.clone(), output.clone()).unwrap_err();
            assert!(
                err.contains("is nested under the"),
                "unexpected error for {}: {err}",
                output.display(),
            );
            assert!(
                !output.exists(),
                "{} was created despite being rejected",
                output.display(),
            );
        }
    }

    #[test]
    fn merge_refuses_colliding_canisters() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1", "c2"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = tmp.path().join("merged");

        let err = do_merge(base, source, output.clone()).unwrap_err();

        assert!(err.contains("holds c2 in both"), "unexpected error: {err}");
    }

    #[test]
    fn merge_refuses_an_existing_output() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = checkpoint(tmp.path(), "merged", &[]);

        let err = do_merge(base, source, output).unwrap_err();

        assert!(err.contains("already exists"), "unexpected error: {err}");
    }

    #[test]
    fn resolve_handles_a_relative_path() {
        // A bare relative output used to run out of ancestors before reaching the
        // directory it is relative to, and was rejected as having none.
        let resolved = resolve(Path::new("merged")).unwrap();

        assert!(
            resolved.is_absolute(),
            "{} is not absolute",
            resolved.display()
        );
        assert_eq!(resolved.file_name().unwrap(), "merged");
        assert_eq!(
            resolved,
            std::env::current_dir().unwrap().join("merged"),
            "a relative path should resolve against the working directory",
        );
    }

    #[test]
    fn merge_refuses_an_existing_staging_directory() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = tmp.path().join("merged");
        // What an interrupted merge would have left behind.
        fs::create_dir(staging_path(&output).unwrap()).unwrap();

        let err = do_merge(base, source, output.clone()).unwrap_err();

        assert!(err.contains("interrupted merge"), "unexpected error: {err}");
        assert!(!output.exists());
    }

    #[test]
    fn merge_leaves_nothing_behind_when_it_fails() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        // A directory where the subnet merged marker belongs cannot be written as
        // a file, so the merge fails with both checkpoints already linked in.
        fs::create_dir(base.join(SUBNET_MERGED_FILE)).unwrap();
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap_err();

        assert!(!output.exists(), "the output was left behind");
        assert!(
            !staging_path(&output).unwrap().exists(),
            "the staging directory was left behind",
        );
    }

    #[test]
    fn merge_refuses_a_missing_input() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let missing = tmp.path().join("missing");
        let output = tmp.path().join("merged");

        let err = do_merge(base.clone(), missing.clone(), output.clone()).unwrap_err();
        assert!(
            err.contains("source checkpoint") && err.contains("not a directory"),
            "unexpected error: {err}"
        );

        let err = do_merge(missing, base, output).unwrap_err();
        assert!(
            err.contains("base checkpoint") && err.contains("not a directory"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn merge_tolerates_a_source_without_snapshots() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        fs::remove_dir_all(source.join(SNAPSHOTS_DIR)).unwrap();
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap();

        assert_eq!(entries(&output.join(CANISTER_STATES_DIR)), ["c1", "c2"]);
        assert_eq!(entries(&output.join(SNAPSHOTS_DIR)), ["c1"]);
    }
}
