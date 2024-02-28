use crate::page_map::storage::StorageLayout;
use ic_types::Height;
use std::path::PathBuf;

pub struct TestStorageLayout {
    pub base: PathBuf,
    pub overlay_dst: PathBuf,
    pub existing_overlays: Vec<PathBuf>,
}

impl StorageLayout for TestStorageLayout {
    fn base(&self) -> PathBuf {
        self.base.clone()
    }
    fn overlay(&self, _height: Height) -> PathBuf {
        self.overlay_dst.clone()
    }
    fn existing_overlays(&self) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        Ok(self.existing_overlays.clone())
    }
}
