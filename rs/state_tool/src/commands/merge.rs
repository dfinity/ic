//! Assembles the merged state of a subnet merge.

use ic_protobuf::state::system_metadata::v1 as pb_metadata;
use ic_state_layout::{CANISTER_STATES_DIR, CheckpointLayout, SNAPSHOTS_DIR, WriteOnly};
use ic_types::Height;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The height of a checkpoint is part of the name of its directory, which the
/// caller picks, so the layout below is only ever used to name files within it.
const HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED: Height = Height::new(0);

/// Assembles the checkpoint at `output` from the checkpoints at `base` and
/// `source`: it holds everything of `base`, with the canisters and canister
/// snapshots of `source` added to those of `base`, and is marked as the product
/// of a subnet merge.
///
/// Only the canisters and their snapshots are taken over from `source`.
/// Everything else (system metadata, subnet queues, ingress history, ...) is
/// `base`'s. In particular, the ingress history of `source` is deliberately not
/// merged in: the subnet merged marker makes the replica re-register the ingress
/// messages of the merged-in canisters that are still in progress.
///
/// File contents are hard linked rather than copied, so this is cheap no matter
/// how large the two states are. That makes `output` share the storage of
/// `base` and `source`, which is sound because checkpoints are immutable: the
/// links are only ever read afterwards.
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

    link_tree(&base, &output)?;

    for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
        let source_dir = source.join(dir);
        if !source_dir.exists() {
            continue;
        }
        let output_dir = output.join(dir);
        // The canisters of the two subnets are disjoint, as the source subnet
        // hosts the canister ID ranges that the merge reassigns to the
        // destination subnet. A collision would mean that the two checkpoints
        // do not belong to the same merge, so refuse rather than pick a winner.
        if let Some(name) = common_entry(&output_dir, &source_dir)? {
            return Err(format!(
                "{} holds {name} in both {} and {}",
                dir,
                base.display(),
                source.display()
            ));
        }
        link_tree(&source_dir, &output_dir)?;
    }

    let layout = CheckpointLayout::<WriteOnly>::new_untracked(
        output.clone(),
        HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED,
    )
    .map_err(|err| format!("failed to create the checkpoint layout: {err:?}"))?;
    layout
        .subnet_merged_marker()
        .serialize(pb_metadata::SubnetMerged { merged: true })
        .map_err(|err| format!("failed to write the subnet merged marker: {err:?}"))?;

    // `base` was a checkpoint of a running subnet, so it holds no unverified
    // checkpoint marker; but a state that was downloaded and reassembled by
    // hand may, and the state manager must not take `output` for unverified.
    let unverified_marker = layout.unverified_checkpoint_marker();
    if unverified_marker.exists() {
        fs::remove_file(&unverified_marker)
            .map_err(|err| format!("failed to remove {}: {err}", unverified_marker.display()))?;
    }

    Ok(())
}

/// Replicates the directory tree rooted at `from` under `to`, hard linking every
/// file. Directories that already exist under `to` are reused, so a tree can be
/// overlaid onto another one.
///
/// The directories are created writable, unlike the read-only ones of a
/// checkpoint, so that a subsequent call can overlay onto them.
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
    use ic_state_layout::{CompleteCheckpointLayout, UNVERIFIED_CHECKPOINT_MARKER};
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    /// Creates a checkpoint-shaped directory under `root`, holding a
    /// `system_metadata.pbuf` and a canister directory (with a snapshot
    /// directory of the same name) per entry of `canisters`.
    fn checkpoint(root: &Path, name: &str, canisters: &[&str]) -> PathBuf {
        let checkpoint = root.join(name);
        fs::create_dir_all(&checkpoint).unwrap();
        fs::write(checkpoint.join("system_metadata.pbuf"), name).unwrap();
        for canister in canisters {
            for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
                let canister_dir = checkpoint.join(dir).join(canister);
                fs::create_dir_all(&canister_dir).unwrap();
                fs::write(canister_dir.join("canister.pbuf"), *canister).unwrap();
            }
        }
        checkpoint
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
    }

    #[test]
    fn merge_keeps_everything_else_from_base() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap();

        assert_eq!(
            fs::read_to_string(output.join("system_metadata.pbuf")).unwrap(),
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
                .join("canister.pbuf")
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
    fn merge_removes_the_unverified_checkpoint_marker() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &["c1"]);
        fs::write(base.join(UNVERIFIED_CHECKPOINT_MARKER), "").unwrap();
        let source = checkpoint(tmp.path(), "source", &["c2"]);
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap();

        assert!(!output.join(UNVERIFIED_CHECKPOINT_MARKER).exists());
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
