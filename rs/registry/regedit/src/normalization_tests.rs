use super::{expand, normalize};
use crate::{
    args::{SourceSpec, VersionSpec},
    snapshot, source,
};

use crate::tests::run_ic_prep;

#[test]
fn normalization() {
    let (_guard, ic_prep_dir) = run_ic_prep();
    let src_spec = SourceSpec::LocalStore(ic_prep_dir.registry_local_store_path());

    let cl = source::get_changelog(src_spec).unwrap();

    let snapshot =
        snapshot::changelog_to_snapshot(cl, VersionSpec::RelativeToLatest(0)).unwrap();

    let (normalized, state) = normalize(snapshot.0.clone());
    let expanded = expand(&state, normalized);

    assert_eq!(snapshot, expanded);
}
