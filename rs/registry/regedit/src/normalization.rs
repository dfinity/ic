use crate::{json, snapshot::Snapshot};
use ic_base_types::PrincipalId;
use ic_crypto_sha::Sha256;
use serde_json::Value;
use std::{collections::BTreeMap, convert::TryFrom, ops::Range, str::FromStr};

const LARGE_ARRAY_MIN_SIZE: usize = 33;
const BIN_DATA_SHA256: &str = "(binary-data|sha256)";
const PRINCIPAL_ID: &str = "(principal-id)";
const BIN_DATA: &str = "(binary-data)";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedSnapshot(pub Value);

pub fn normalize(mut value: Value) -> (NormalizedSnapshot, Sha256InvMap) {
    let mut inv_map = Sha256InvMap::default();
    // turn all (potential) principal ids into textual representations of principal
    // ids.
    mangle_json_value(&mut value, &mut byte_array_to_principal_id);
    // replace all large byte blobs with hashes
    mangle_json_value(&mut value, &mut |v: &Value| inv_map.reduce(v));
    // replace all remaining byte blobs with hex representations
    mangle_json_value(&mut value, &mut hex_encode_small_arrays);

    (NormalizedSnapshot(value), inv_map)
}

pub fn expand(inv_map: &Sha256InvMap, snapshot: NormalizedSnapshot) -> Snapshot {
    let mut value = snapshot.0;
    // turn all (potential) principal ids into textual representations of principal
    // ids.
    mangle_json_value(&mut value, &mut principal_id_to_bytes);
    // replace all large byte blobs with hashes
    mangle_json_value(&mut value, &mut |v: &Value| inv_map.expand(v));
    // replace all remaining byte blobs with hex representations
    mangle_json_value(&mut value, &mut hex_decode_arrays);

    Snapshot(value)
}

#[derive(Clone, Default, Debug)]
pub struct Sha256InvMap {
    m: BTreeMap<[u8; 32], Vec<u8>>,
}

impl Sha256InvMap {
    fn reduce(&mut self, v: &Value) -> Option<Value> {
        if let Some(bytes) = as_byte_array_len(v, LARGE_ARRAY_MIN_SIZE..usize::MAX) {
            let digest = Sha256::hash(bytes.as_slice());
            self.m.insert(digest, bytes);
            let mut res = BIN_DATA_SHA256.to_string();
            res.push_str(&bytes_to_hex(digest.as_ref()));
            return Some(json::assert_to_value(res));
        }
        None
    }

    #[allow(dead_code)]
    fn expand(&self, v: &Value) -> Option<Value> {
        if let Some(s) = v.as_str() {
            if let Some(s) = s.strip_prefix(BIN_DATA_SHA256) {
                let digest = hex_to_sha256_digest(s);
                let val = self
                    .m
                    .get(&digest)
                    .expect("Could not find sha256 value.")
                    .clone();
                return Some(json::assert_to_value(val));
            }
        }
        None
    }
}

fn mangle_json_value<F>(value: &mut Value, f: &mut F)
where
    F: FnMut(&Value) -> Option<Value>,
{
    if let Some(v) = f(value) {
        *value = v;
    } else if let Some(a) = value.as_array_mut() {
        a.iter_mut().for_each(|mut v| mangle_json_value(&mut v, f));
    } else if let Some(o) = value.as_object_mut() {
        o.iter_mut()
            .for_each(|(_, mut v)| mangle_json_value(&mut v, f));
    }
}

fn byte_array_to_principal_id(value: &Value) -> Option<Value> {
    if let Some(bytes) = as_byte_array_len(value, 1..PrincipalId::MAX_LENGTH_IN_BYTES + 1) {
        return PrincipalId::try_from(bytes.as_slice()).ok().map(|v| {
            let mut res = PRINCIPAL_ID.to_string();
            res.push_str(&v.to_string());
            json::assert_to_value(res)
        });
    }
    None
}

fn principal_id_to_bytes(value: &Value) -> Option<Value> {
    if let Some(s) = value.as_str() {
        if let Some(s) = s.strip_prefix(PRINCIPAL_ID) {
            let principal_id = PrincipalId::from_str(s).expect("Not a principal id.");
            return Some(json::assert_to_value(principal_id.as_slice()));
        }
    }
    None
}

fn hex_encode_small_arrays(value: &Value) -> Option<Value> {
    if let Some(bytes) = as_byte_array_len(value, 0..LARGE_ARRAY_MIN_SIZE) {
        let mut res = BIN_DATA.to_string();
        res.push_str(&bytes_to_hex(bytes.as_slice()));
        return Some(json::assert_to_value(res));
    }
    None
}

fn hex_decode_arrays(value: &Value) -> Option<Value> {
    if let Some(s) = value.as_str() {
        if let Some(s) = s.strip_prefix(BIN_DATA) {
            let bytes = hex_to_bytes(s);
            return Some(json::assert_to_value(bytes));
        }
    }
    None
}

fn as_byte_array_len(value: &Value, range: Range<usize>) -> Option<Vec<u8>> {
    if let Some(v) = value.as_array() {
        if v.iter().all(|f| f.as_u64().unwrap_or(0x100) < 0x100) && range.contains(&v.len()) {
            let bytes = v.iter().map(|x| x.as_u64().unwrap() as u8).collect();
            return Some(bytes);
        }
    }
    None
}

fn bytes_to_hex(data: &[u8]) -> String {
    let mut res = String::new();
    for b in data {
        res.push_str(&format!("{:02X}", b))
    }
    res
}

fn hex_to_sha256_digest(s: &str) -> [u8; 32] {
    let mut res = [0u8; 32];
    for (i, c) in res.iter_mut().enumerate() {
        *c = (hexdigit_to_u8(s.as_bytes()[2 * i]) << 4) + hexdigit_to_u8(s.as_bytes()[2 * i + 1]);
    }
    res
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    assert_eq!(
        s.len() % 2,
        0,
        "Hex-encoded value must have an even length."
    );
    s.as_bytes()
        .chunks(2)
        .map(|c| (hexdigit_to_u8(c[0]) << 4) + hexdigit_to_u8(c[1]))
        .collect()
}

#[inline]
fn hexdigit_to_u8(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 0xA,
        b'a'..=b'f' => c - b'a' + 0xA,
        _ => panic!("Not a hex digit: {}", c),
    }
}

#[cfg(test)]
mod tests {
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
}
