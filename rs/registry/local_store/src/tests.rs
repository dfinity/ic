use super::*;
use rand::prelude::*;
use tempfile::TempDir;

#[test]
fn empty_changelog_after_clear() {
    let tempdir = TempDir::new().unwrap();
    let store = LocalStoreImpl::new(tempdir.path());
    let mut rng = rand::thread_rng();
    let changelog = get_random_changelog(1, &mut rng);

    store
        .store(RegistryVersion::from(1), changelog[0].clone())
        .unwrap();

    store.clear().unwrap();

    assert!(
        store
            .get_changelog_since_version(RegistryVersion::from(0))
            .unwrap()
            .is_empty()
    );

    let changelog = get_random_changelog(1, &mut rng);
    store
        .store(RegistryVersion::from(1), changelog[0].clone())
        .unwrap();

    assert_eq!(
        store
            .get_changelog_since_version(RegistryVersion::from(0))
            .unwrap(),
        changelog
    );
}

#[test]
#[should_panic(expected = "Version must be > 0")]
fn storing_at_version_0_fails() {
    let tempdir = TempDir::new().unwrap();
    let store = LocalStoreImpl::new(tempdir.path());
    let mut rng = rand::thread_rng();
    let changelog = get_random_changelog(1, &mut rng);

    store
        .store(RegistryVersion::from(0), changelog[0].clone())
        .unwrap()
}

#[test]
fn can_extend_and_restore() {
    let tempdir = TempDir::new().unwrap();
    let store = LocalStoreImpl::new(tempdir.path());
    let mut rng = rand::thread_rng();

    let mut changelog = get_random_changelog(200, &mut rng);
    changelog.iter().enumerate().for_each(|(i, c)| {
        store
            .store(RegistryVersion::from((i + 1) as u64), c.clone())
            .unwrap()
    });

    for i in (0..changelog.len()).step_by(10) {
        let cl = store
            .get_changelog_since_version(RegistryVersion::from(i as u64))
            .unwrap();
        assert_eq!(&changelog[i..], cl.as_slice());
    }

    let mut new_changelog = get_random_changelog(100, &mut rng);
    new_changelog.iter().enumerate().for_each(|(i, c)| {
        store
            .store(RegistryVersion::from((i + 201) as u64), c.clone())
            .unwrap()
    });

    changelog.append(&mut new_changelog);
    for i in (0..changelog.len()).step_by(10) {
        let cl = store
            .get_changelog_since_version(RegistryVersion::from(i as u64))
            .unwrap();
        assert_eq!(&changelog[i..], cl.as_slice());
    }
}

fn get_random_changelog(n: usize, rng: &mut ThreadRng) -> Changelog {
    // some pseudo random entries
    (0..n)
        .map(|_i| {
            let k = rng.r#gen::<usize>() % 64 + 2;
            (0..(k + 2)).map(|k| key_mutation(k, rng)).collect()
        })
        .collect()
}

fn key_mutation(k: usize, rng: &mut ThreadRng) -> KeyMutation {
    let s = rng.next_u64() & 64;
    let set: bool = rng.r#gen();
    KeyMutation {
        key: k.to_string(),
        value: if set {
            Some((0..s as u8).collect())
        } else {
            None
        },
    }
}

#[test]
fn mainnet_delta_can_be_read() {
    let changelog = get_mainnet_delta();
    assert_eq!(changelog.len(), 0x6dc1);
}

fn get_mainnet_delta() -> Changelog {
    compact_delta_to_changelog(ic_registry_local_store_artifacts::MAINNET_DELTA_00_6D_C1)
        .expect("")
        .1
}
