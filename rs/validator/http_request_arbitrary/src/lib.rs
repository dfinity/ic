use arbitrary::{Arbitrary, Result, Unstructured};
use ic_base_types::CanisterId;
use ic_crypto_tree_hash::{Label, Path};
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
    HttpReadStateContent, HttpUserQuery,
};
use std::ops::RangeInclusive;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AnonymousContent {
    pub canister_id: Blob,
    pub paths: Vec<Path>,
    pub method_name: String,
    pub arg: Blob,
    pub ingress_expiry: u64,
    pub nonce: Option<Blob>,
}

impl AnonymousContent {
    fn sender(&self) -> Blob {
        const ANONYMOUS_SENDER: u8 = 0x04;
        Blob(vec![ANONYMOUS_SENDER])
    }
}

impl<'a> Arbitrary<'a> for AnonymousContent {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(AnonymousContent {
            canister_id: somewhat_arbitrary_canister_id(u)?,
            paths: arbitrary_tree_paths(u, 0..=50_000, 0..=50_000)?,
            method_name: String::arbitrary(u)?,
            arg: arbitrary_blob(u)?,
            ingress_expiry: u64::arbitrary(u)?,
            nonce: arbitrary_option_blob(u)?,
        })
    }
}

impl From<AnonymousContent> for HttpCallContent {
    fn from(content: AnonymousContent) -> Self {
        let sender = content.sender();
        HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: content.canister_id,
                method_name: content.method_name,
                arg: content.arg,
                sender,
                ingress_expiry: content.ingress_expiry,
                nonce: content.nonce,
            },
        }
    }
}

impl From<AnonymousContent> for HttpQueryContent {
    fn from(content: AnonymousContent) -> Self {
        let sender = content.sender();
        HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: content.canister_id,
                method_name: content.method_name,
                arg: content.arg,
                sender,
                ingress_expiry: content.ingress_expiry,
                nonce: content.nonce,
            },
        }
    }
}

impl From<AnonymousContent> for HttpReadStateContent {
    fn from(content: AnonymousContent) -> Self {
        let sender = content.sender();
        HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                sender,
                paths: content.paths,
                ingress_expiry: content.ingress_expiry,
                nonce: content.nonce,
            },
        }
    }
}

fn arbitrary_blob(u: &mut Unstructured) -> Result<Blob> {
    Ok(Blob(<Vec<u8>>::arbitrary(u)?))
}

/// A CanisterId wraps a PrincipalId, whose length is at most 29 bytes.
/// We want to produce syntactically correct CanisterIds to avoid the fuzzer stopping too early,
/// while avoiding biasing the fuzzer too much.
fn somewhat_arbitrary_canister_id(u: &mut Unstructured) -> Result<Blob> {
    match u8::arbitrary(u)? % 4 {
        0 => arbitrary_blob(u),
        _ => {
            let bytes = arbitrary_variable_length_vector(u, 0..=29)?;
            assert!(CanisterId::try_from(&bytes).is_ok());
            Ok(Blob(bytes))
        }
    }
}

fn arbitrary_variable_length_vector<'a, T: Arbitrary<'a>>(
    u: &mut Unstructured<'a>,
    length_range: RangeInclusive<usize>,
) -> Result<Vec<T>> {
    let length: usize = u.int_in_range(length_range)?;
    let mut result = Vec::with_capacity(length);
    for _ in 0..length {
        result.push(T::arbitrary(u)?)
    }
    Ok(result)
}

fn arbitrary_option_blob<'a>(u: &mut Unstructured<'a>) -> Result<Option<Blob>> {
    Ok(if <bool as Arbitrary<'a>>::arbitrary(u)? {
        Some(arbitrary_blob(u)?)
    } else {
        None
    })
}

fn arbitrary_tree_paths(
    u: &mut Unstructured,
    num_paths_range: RangeInclusive<usize>,
    num_labels_range: RangeInclusive<usize>,
) -> Result<Vec<Path>> {
    let num_paths: usize = u.int_in_range(num_paths_range)?;
    let mut result = Vec::with_capacity(num_paths);
    for _ in 0..num_paths {
        result.push(arbitrary_tree_path(u, num_labels_range.clone())?)
    }
    Ok(result)
}

fn arbitrary_tree_path(
    u: &mut Unstructured,
    num_labels_range: RangeInclusive<usize>,
) -> Result<Path> {
    let num_labels: usize = u.int_in_range(num_labels_range)?;
    let mut result = Vec::with_capacity(num_labels);
    for _ in 0..num_labels {
        result.push(arbitrary_tree_label(u)?)
    }
    Ok(Path::from(result))
}

fn arbitrary_tree_label(u: &mut Unstructured) -> Result<Label> {
    Ok(Label::from(<Vec<u8>>::arbitrary(u)?))
}
