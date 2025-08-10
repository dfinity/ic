use ic_crypto_sha2::Sha256;
use ic_types::state_sync::StateSyncVersion;

/// Trait specifying how a type should be hashed when it's included into a
/// manifest.
pub(crate) trait ManifestHash {
    fn update_hash(&self, h: &mut Sha256);
}

impl<T: ManifestHash> ManifestHash for &T {
    fn update_hash(&self, h: &mut Sha256) {
        (*self).update_hash(h)
    }
}

impl ManifestHash for u64 {
    fn update_hash(&self, h: &mut Sha256) {
        h.write(&self.to_be_bytes()[..])
    }
}

impl ManifestHash for u32 {
    fn update_hash(&self, h: &mut Sha256) {
        h.write(&self.to_be_bytes()[..])
    }
}

impl ManifestHash for u8 {
    fn update_hash(&self, h: &mut Sha256) {
        h.write(&[*self][..])
    }
}

impl ManifestHash for str {
    fn update_hash(&self, h: &mut Sha256) {
        (self.len() as u32).update_hash(h);
        h.write(self.as_bytes())
    }
}

impl ManifestHash for [u8] {
    fn update_hash(&self, h: &mut Sha256) {
        h.write(self)
    }
}

impl ManifestHash for StateSyncVersion {
    fn update_hash(&self, h: &mut Sha256) {
        (*self as u32).update_hash(h)
    }
}

fn hasher_for_domain(s: &str) -> Sha256 {
    let mut h = Sha256::new();
    h.write(&[s.len() as u8][..]);
    h.write(s.as_bytes());
    h
}

pub fn manifest_hasher() -> Sha256 {
    hasher_for_domain("ic-state-manifest")
}

pub fn meta_manifest_hasher() -> Sha256 {
    hasher_for_domain("ic-state-meta-manifest")
}

pub fn sub_manifest_hasher() -> Sha256 {
    hasher_for_domain("ic-state-sub-manifest")
}

pub fn file_hasher() -> Sha256 {
    hasher_for_domain("ic-state-file")
}

pub fn chunk_hasher() -> Sha256 {
    hasher_for_domain("ic-state-chunk")
}
