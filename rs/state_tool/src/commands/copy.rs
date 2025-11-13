use ic_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::state::v1 as pb;
use ic_state_layout::StateLayout;
use ic_types::Height;
use prost::Message;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub enum Heights {
    All,
    Latest,
    Explicit(Vec<(Height, Option<Height>)>),
}

/// Copy checkpoints from the state directory at `source` to the state directory at `destination`.
///
/// If `heights` is `Heights::All`, all checkpoints from the source are copied. If it is `Heights::Latest` only the maximum height
/// from `src` is copied (no-op if there are no checkpoints).
/// Otherwise, only listed checkpoints are copied.
/// Optionally, if the heights are listed explicitly then the copied checkpoints can be given a different height in the destination.
///
/// Apart from copying the checkpoints, the relevant entries are also copied from the `states_metadata.pbuf` file, containing the manifest.
pub fn do_copy(source: PathBuf, destination: PathBuf, heights: Heights) -> Result<(), String> {
    let src_layout = StateLayout::new_no_init(no_op_logger(), source, &MetricsRegistry::new());
    let dst_layout =
        StateLayout::try_new(no_op_logger(), destination, &MetricsRegistry::new()).unwrap();

    let heights = match heights {
        Heights::All => src_layout
            .checkpoint_heights()
            .unwrap()
            .into_iter()
            .map(|h| (h, None))
            .collect(),
        Heights::Latest => src_layout
            .checkpoint_heights()
            .unwrap()
            .last()
            .map(|h| vec![(*h, None)])
            .unwrap_or_default(),
        Heights::Explicit(heights) => heights,
    };

    // Replace (h, None) with (h, h) and (h, Some(x)) with (h, x)
    let heights = heights
        .into_iter()
        .map(|(src, dst)| {
            let dst = dst.unwrap_or(src);
            (src, dst)
        })
        .collect();

    do_copy_with_state_layouts(&src_layout, &dst_layout, heights)
}

fn do_copy_with_state_layouts(
    src_layout: &StateLayout,
    dst_layout: &StateLayout,
    heights: Vec<(Height, Height)>,
) -> Result<(), String> {
    if heights.is_empty() {
        return Ok(());
    }

    // Check if all checkpoints exist at the source and none exist at the destination.
    // We do this before copying anything to avoid partially copying checkpoints.
    for (src_height, dst_height) in heights.iter() {
        if let Ok(cp_layout) = dst_layout.checkpoint_verified(*dst_height) {
            return Err(format!(
                "Checkpoint {} already exists at {}",
                dst_height,
                cp_layout.raw_path().display()
            ));
        }

        if src_layout.checkpoint_verified(*src_height).is_err() {
            return Err(format!("Checkpoint {src_height} does not exist at src"));
        }
    }

    let src_metadata = load_metadata_proto(&src_layout.states_metadata())
        .map_err(|e| format!("Failed to read metadata: {e}"))?;
    let mut dst_metadata = load_metadata_proto(&dst_layout.states_metadata())
        .map_err(|e| format!("Failed to read metadata: {e}"))?;

    for (src_height, dst_height) in heights {
        dst_layout
            .copy_and_sync_checkpoint(
                &format!("import_{dst_height}"),
                &src_layout
                    .checkpoints()
                    .join(StateLayout::checkpoint_name(src_height)),
                &dst_layout
                    .checkpoints()
                    .join(StateLayout::checkpoint_name(dst_height)),
                None,
            )
            .map_err(|e| format!("Failed to copy checkpoint. Not all states might have been copied and some metadata might be missing: {e}"))?;

        if let Some(src_metadata_entry) = src_metadata.by_height.get(&src_height.get()) {
            dst_metadata
                .by_height
                .insert(dst_height.get(), src_metadata_entry.clone());
        }
    }

    write_metadata_proto(&dst_layout.states_metadata(), &dst_metadata).map_err(|e| {
        format!(
            "Failed to write metadata. Metadata might be missing or corrupted in destination: {e}"
        )
    })?;

    Ok(())
}

fn write_metadata_proto(path: &Path, metadata: &pb::StatesMetadata) -> Result<(), std::io::Error> {
    let mut w = std::fs::File::create(path)?;
    let mut buf = Vec::new();
    metadata.encode(&mut buf)?;
    w.write_all(&buf[..])?;
    Ok(())
}

fn load_metadata_proto(path: &Path) -> Result<pb::StatesMetadata, std::io::Error> {
    if path.exists() {
        let mut file = std::fs::File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(pb::StatesMetadata::decode(&buf[..]).unwrap_or_default())
    } else {
        Ok(pb::StatesMetadata::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_state_machine_tests::StateMachineBuilder;
    use tempfile::TempDir;

    #[test]
    fn copy_test() {
        let env = StateMachineBuilder::new().build();
        env.checkpointed_tick();
        env.state_manager.flush_tip_channel();

        let tmp_dir = TempDir::new().unwrap();
        let dst_layout = StateLayout::try_new(
            no_op_logger(),
            tmp_dir.path().to_path_buf(),
            &MetricsRegistry::new(),
        )
        .unwrap();

        assert!(dst_layout.checkpoint_heights().unwrap().is_empty());
        assert!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height
                .is_empty()
        );

        do_copy_with_state_layouts(
            env.state_manager.state_layout(),
            &dst_layout,
            vec![(Height::new(1), Height::new(1))],
        )
        .unwrap();

        assert_eq!(
            dst_layout.checkpoint_heights().unwrap(),
            vec![Height::new(1)]
        );
        assert_eq!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height
                .len(),
            1
        );
        assert!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height[&1]
                .manifest
                .is_some()
        );

        env.checkpointed_tick();
        env.checkpointed_tick();
        env.state_manager.flush_tip_channel();

        do_copy_with_state_layouts(
            env.state_manager.state_layout(),
            &dst_layout,
            vec![(Height::new(3), Height::new(3))],
        )
        .unwrap();

        assert_eq!(
            dst_layout.checkpoint_heights().unwrap(),
            vec![Height::new(1), Height::new(3)]
        );
    }

    #[test]
    fn multiple_copy_test() {
        let env = StateMachineBuilder::new()
            .with_remove_old_states(false)
            .build();
        env.checkpointed_tick();
        env.checkpointed_tick();
        env.checkpointed_tick();
        env.state_manager.flush_tip_channel();

        let tmp_dir = TempDir::new().unwrap();
        let dst_layout = StateLayout::try_new(
            no_op_logger(),
            tmp_dir.path().to_path_buf(),
            &MetricsRegistry::new(),
        )
        .unwrap();

        assert!(dst_layout.checkpoint_heights().unwrap().is_empty());
        assert!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height
                .is_empty()
        );

        do_copy_with_state_layouts(
            env.state_manager.state_layout(),
            &dst_layout,
            vec![
                (Height::new(1), Height::new(1)),
                (Height::new(3), Height::new(3)),
            ],
        )
        .unwrap();

        assert_eq!(
            dst_layout.checkpoint_heights().unwrap(),
            vec![Height::new(1), Height::new(3)]
        );
        assert_eq!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height
                .len(),
            2
        );
        assert!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height[&1]
                .manifest
                .is_some()
        );
        assert!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height[&3]
                .manifest
                .is_some()
        );
    }

    #[test]
    fn rename_copy_test() {
        let env = StateMachineBuilder::new().build();
        env.checkpointed_tick();
        env.state_manager.flush_tip_channel();

        let tmp_dir = TempDir::new().unwrap();
        let dst_layout = StateLayout::try_new(
            no_op_logger(),
            tmp_dir.path().to_path_buf(),
            &MetricsRegistry::new(),
        )
        .unwrap();

        assert!(dst_layout.checkpoint_heights().unwrap().is_empty());
        assert!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height
                .is_empty()
        );

        do_copy_with_state_layouts(
            env.state_manager.state_layout(),
            &dst_layout,
            vec![(Height::new(1), Height::new(4))],
        )
        .unwrap();

        assert_eq!(
            dst_layout.checkpoint_heights().unwrap(),
            vec![Height::new(4)]
        );
        assert_eq!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height
                .len(),
            1
        );
        assert!(
            load_metadata_proto(&dst_layout.states_metadata())
                .unwrap()
                .by_height[&4]
                .manifest
                .is_some()
        );
    }
}
