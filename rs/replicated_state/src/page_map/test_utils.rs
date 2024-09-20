use crate::page_map::storage::{Shard, StorageLayout, StorageResult};
use ic_types::Height;
use std::path::{Path, PathBuf};

pub struct TestStorageLayout {
    pub base: PathBuf,
    pub overlay_dst: PathBuf,
    pub existing_overlays: Vec<PathBuf>,
}

impl StorageLayout for TestStorageLayout {
    fn base(&self) -> PathBuf {
        self.base.clone()
    }
    fn overlay(&self, _height: Height, shard: Shard) -> PathBuf {
        assert_eq!(shard.get(), 0);
        self.overlay_dst.clone()
    }
    fn existing_overlays(&self) -> StorageResult<Vec<PathBuf>> {
        Ok(self.existing_overlays.clone())
    }
    fn overlay_height(&self, _path: &Path) -> StorageResult<Height> {
        unimplemented!()
    }
    fn overlay_shard(&self, _path: &Path) -> StorageResult<Shard> {
        unimplemented!()
    }
}

pub fn base_only_storage_layout(path: PathBuf) -> TestStorageLayout {
    TestStorageLayout {
        base: path,
        overlay_dst: "".into(),
        existing_overlays: Vec::new(),
    }
}

pub struct ShardedTestStorageLayout {
    pub base: PathBuf,
    pub dir_path: PathBuf,
    pub overlay_suffix: String,
}

impl StorageLayout for ShardedTestStorageLayout {
    fn base(&self) -> PathBuf {
        self.base.clone()
    }
    fn overlay(&self, height: Height, shard: Shard) -> PathBuf {
        self.dir_path.join(format!(
            "{:06}_{:03}_{}",
            height.get(),
            shard.get(),
            self.overlay_suffix
        ))
    }
    fn existing_overlays(&self) -> StorageResult<Vec<PathBuf>> {
        let mut result: Vec<_> = std::fs::read_dir(&self.dir_path)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .ends_with(&self.overlay_suffix)
            })
            .map(|entry| entry.unwrap().path())
            .collect();
        result.sort_unstable();
        Ok(result)
    }
    fn overlay_height(&self, path: &Path) -> StorageResult<Height> {
        let file = path.file_name().unwrap();
        Ok(Height::from(
            file.to_str().unwrap()[0..6].parse::<u64>().unwrap(),
        ))
    }
    fn overlay_shard(&self, path: &Path) -> StorageResult<Shard> {
        let file = path.file_name().unwrap();
        Ok(Shard::from(
            file.to_str().unwrap()[7..10].parse::<u64>().unwrap(),
        ))
    }
}
