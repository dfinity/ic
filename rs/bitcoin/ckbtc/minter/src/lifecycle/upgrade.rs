use crate::state::{replace_state, take_state};
use ic_cdk::api::stable::{StableReader, StableWriter};

pub fn pre_upgrade() {
    ic_cdk::println!("Executing pre upgrade");
    ciborium::ser::into_writer(&take_state(|s| s), StableWriter::default())
        .expect("failed to encode minter state");
}

pub fn post_upgrade() {
    ic_cdk::println!("Executing post upgrade");
    replace_state(
        ciborium::de::from_reader(StableReader::default()).expect("failed to decode minter state"),
    );
}
