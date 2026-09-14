//! Assembles the merged state of a subnet merge.

use ic_protobuf::state::system_metadata::v1 as pb_metadata;
use ic_state_layout::{CANISTER_STATES_DIR, CheckpointLayout, SNAPSHOTS_DIR, WriteOnly};
use ic_types::Height;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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
///
/// `output` has to be outside both inputs, which is left to the caller rather
/// than checked. Under `base`, or under `source`'s canister or snapshot
/// directory, the linking finds the output and links it into itself until the
/// merge fails; anywhere else under `source` it is never reached and the merge
/// succeeds, leaving the merged checkpoint inside the source checkpoint.
pub fn do_merge(base: PathBuf, source: PathBuf, output: PathBuf) -> Result<(), String> {
    for (path, name) in [(&base, "base"), (&source, "source")] {
        if !path.is_dir() {
            return Err(format!(
                "the {name} checkpoint {} is not a directory",
                path.display()
            ));
        }
    }
    // Absolute, so that the parent below is a directory rather than the empty
    // path a bare relative output would give.
    let absolute_output = std::path::absolute(&output)
        .map_err(|err| format!("failed to resolve {}: {err}", output.display()))?;
    let parent = absolute_output
        .parent()
        .expect("an absolute path has a parent");
    // The canisters of the two subnets are disjoint, so a collision means these
    // two checkpoints are not from the same merge.
    for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
        if let Some(name) = common_entry(&base.join(dir), &source.join(dir))? {
            return Err(format!(
                "{dir} holds {name} in both {} and {}",
                base.display(),
                source.display()
            ));
        }
    }

    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    fs::create_dir(&output).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{} already exists", output.display())
        } else {
            format!("failed to create {}: {err}", output.display())
        }
    })?;

    let result = assemble(&base, &source, &output).and_then(|()| {
        // Creating a directory is not durable until the directory it was
        // created in is synced.
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|err| format!("failed to sync {}: {err}", parent.display()))
    });
    // A merge that reports a failure must not leave a checkpoint behind. The
    // original error is the one the caller needs, so a cleanup failure is
    // appended to it rather than replacing it.
    if let Err(err) = &result
        && let Err(cleanup) = fs::remove_dir_all(&output)
    {
        return Err(format!(
            "{err}, and {} could not be removed: {cleanup}",
            output.display()
        ));
    }

    result
}

/// Assembles the merged checkpoint at `output`, an existing empty directory.
fn assemble(base: &Path, source: &Path, output: &Path) -> Result<(), String> {
    link_tree(base, output)?;

    for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
        let source_dir = source.join(dir);
        if source_dir.exists() {
            link_tree(&source_dir, &output.join(dir))?;
        }
    }

    // Any height will do: the layout is only asked for the paths of files inside
    // the checkpoint, which do not depend on one.
    let layout = CheckpointLayout::<WriteOnly>::new_untracked(output.to_path_buf(), Height::new(0))
        .map_err(|err| format!("failed to create the checkpoint layout: {err:?}"))?;
    layout
        .subnet_merged_marker()
        .serialize(pb_metadata::SubnetMerged { merged: true })
        .map_err(|err| format!("failed to write the subnet merged marker: {err:?}"))?;

    // The linked-in files are read-only already, being the files of `base` and
    // `source`; the marker written above is not.
    layout
        .mark_files_readonly_and_sync(/* thread_pool= */ None, /* perform_sync= */ true)
        .map_err(|err| format!("failed to mark the merged checkpoint read-only: {err:?}"))?;

    Ok(())
}

/// Replicates the directory tree rooted at `from` under `to`, hard linking every
/// file. Directories that already exist under `to` are reused and are created
/// writable, so that trees can be overlaid onto one another.
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

        let layout = CompleteCheckpointLayout::new_untracked(output, Height::new(0)).unwrap();
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
