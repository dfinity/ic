use super::*;
use std::io::Write;

#[test]
fn can_mmap_file() {
    let mut tmp = tempfile::tempfile().expect("failed to create a temporary file");
    tmp.write_all(b"TEST TEST")
        .expect("failed to write data to a tempfile");
    let mmap = ScopedMmap::from_readonly_file(&tmp, 9).expect("failed to mmap a temporary file");
    assert_eq!(mmap.as_slice(), &b"TEST TEST"[..]);
}

#[test]
fn can_mmap_path() {
    let mut tmp = tempfile::NamedTempFile::new().expect("failed to create a temporary file");
    let mmap = ScopedMmap::from_path(tmp.path())
        .unwrap_or_else(|e| panic!("failed to mmap path {}: {}", tmp.path().display(), e));
    assert_eq!(mmap.len(), 0);

    tmp.write_all(b"TEST TEST")
        .unwrap_or_else(|e| panic!("failed to write to {}: {}", tmp.path().display(), e));

    let mmap = ScopedMmap::from_path(tmp.path())
        .unwrap_or_else(|e| panic!("failed to mmap path {}: {}", tmp.path().display(), e));
    assert_eq!(mmap.as_slice(), &b"TEST TEST"[..]);
}
