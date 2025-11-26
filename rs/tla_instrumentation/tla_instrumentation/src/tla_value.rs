use candid::{CandidType, Deserialize, Int as CInt, Nat, Principal};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::{
    fmt,
    fmt::{Display, Formatter},
};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize)]
pub enum TlaValue {
    Set(BTreeSet<TlaValue>),
    Record(BTreeMap<String, TlaValue>),
    Function(BTreeMap<TlaValue, TlaValue>),
    Seq(Vec<TlaValue>),
    Literal(String),
    Constant(String),
    Bool(bool),
    Int(CInt),
    Variant { tag: String, value: Box<TlaValue> },
}

#[derive(Clone, Debug)]
pub enum Diff {
    /// For records and functions, have a fine-grained diff
    RecordDiff(HashMap<String, Box<Diff>>),
    FunctionDiff(HashMap<TlaValue, Box<Diff>>),
    /// For other value types, just record the difference
    Other(Option<TlaValue>, Option<TlaValue>),
}

impl TlaValue {
    /// An approximation of the size of the TLA value, in terms of the number of atoms.
    /// Ignores string lengths or number sizes.
    pub fn size(&self) -> u64 {
        match self {
            TlaValue::Set(set) => set.iter().map(|x| x.size()).sum(),
            TlaValue::Record(map) => map.values().map(|v| 1 + v.size()).sum(),
            TlaValue::Function(map) => map.iter().map(|(k, v)| k.size() + v.size()).sum(),
            TlaValue::Seq(vec) => vec.iter().map(|x| x.size()).sum(),
            TlaValue::Literal(_s) => 1_u64,
            TlaValue::Constant(_s) => 1_u64,
            TlaValue::Bool(_) => 1,
            TlaValue::Int(_) => 1,
            TlaValue::Variant { tag: _, value } => 1 + value.size(),
        }
    }

    /// Returns a list of fields that differ between this value and the other one
    /// The difference is fine-grained, so if a field is a (potentially nested) record or a function,
    /// the difference lists just the fields that differ (respectively, the argument/value pairs that differ)
    pub fn diff(&self, other: &TlaValue) -> Option<Diff> {
        if self == other {
            return None;
        }
        match (self, other) {
            (TlaValue::Record(map1), TlaValue::Record(map2)) => {
                let mut diff = vec![];
                for (k, v1) in map1 {
                    if let Some(v2) = map2.get(k) {
                        let sub_diff = v1.diff(v2);
                        match sub_diff {
                            Some(Diff::RecordDiff(m)) => {
                                diff.extend(
                                    m.into_iter().map(|(k2, dv)| (format!("{k}.{k2}"), dv)),
                                );
                            }
                            Some(Diff::FunctionDiff(m)) => {
                                diff.extend(
                                    m.into_iter().map(|(k2, dv)| (format!("{k}[{k2:?}]"), dv)),
                                );
                            }
                            Some(d @ Diff::Other(_, _)) => {
                                diff.push((k.clone(), Box::new(d)));
                            }
                            None => {}
                        }
                    } else {
                        diff.push((k.clone(), Box::new(Diff::Other(Some(v1.clone()), None))));
                    }
                }
                for (k, v2) in map2 {
                    if !map1.contains_key(k) {
                        diff.push((k.clone(), Box::new(Diff::Other(None, Some(v2.clone())))));
                    }
                }
                if diff.is_empty() {
                    None
                } else {
                    Some(Diff::RecordDiff(diff.into_iter().collect()))
                }
            }
            (TlaValue::Function(map1), TlaValue::Function(map2)) => {
                let mut diff = vec![];
                for (k, v1) in map1 {
                    if let Some(v2) = map2.get(k) {
                        let sub_diff = v1.diff(v2);
                        if let Some(d) = sub_diff {
                            diff.push((k.clone(), Box::new(d)));
                        }
                    } else {
                        diff.push((k.clone(), Box::new(Diff::Other(Some(v1.clone()), None))));
                    }
                }
                for (k, v2) in map2 {
                    if !map1.contains_key(k) {
                        diff.push((k.clone(), Box::new(Diff::Other(None, Some(v2.clone())))));
                    }
                }
                if diff.is_empty() {
                    None
                } else {
                    Some(Diff::FunctionDiff(diff.into_iter().collect()))
                }
            }
            (val1, val2) => {
                if val1 == val2 {
                    None
                } else {
                    Some(Diff::Other(Some(val1.clone()), Some(val2.clone())))
                }
            }
        }
    }
}

impl Display for TlaValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TlaValue::Set(set) => {
                let elements: Vec<_> = set.iter().map(|x| format!("{x}")).collect();
                write!(f, "{{{}}}", elements.join(", "))
            }
            TlaValue::Record(map) => {
                let elements: Vec<_> = map.iter().map(|(k, v)| format!("{k} |-> {v}")).collect();
                write!(f, "[{}]", elements.join(", "))
            }
            TlaValue::Function(map) => {
                if map.is_empty() {
                    f.write_str("[x \\in {} |-> CHOOSE y \\in {}: TRUE]")
                } else {
                    let elements: Vec<_> = map.iter().map(|(k, v)| format!("{k} :> {v}")).collect();
                    write!(f, "({})", elements.join(" @@ "))
                }
            }
            TlaValue::Seq(vec) => {
                let elements: Vec<_> = vec.iter().map(|x| format!("{x}")).collect();
                write!(f, "<<{}>>", elements.join(", "))
            }
            TlaValue::Literal(s) => write!(f, "\"{s}\""),
            TlaValue::Constant(s) => write!(f, "{s}"),
            TlaValue::Bool(b) => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            // Candid likes to pretty print its numbers
            TlaValue::Int(i) => write!(f, "{}", format!("{i}").replace("_", "")),
            TlaValue::Variant { tag, value } => write!(f, "Variant(\"{tag}\", {value})"),
        }
    }
}

impl fmt::Debug for TlaValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TlaValue::Set(set) => {
                let mut debug_set = f.debug_set();
                for elem in set {
                    debug_set.entry(elem);
                }
                debug_set.finish()
            }
            TlaValue::Record(map) => {
                let mut debug_map = f.debug_map();
                for (key, value) in map {
                    debug_map.entry(&format!("\"{key}\""), value);
                }
                debug_map.finish()
            }
            TlaValue::Function(map) => {
                let mut debug_map = f.debug_map();
                for (key, value) in map {
                    debug_map.entry(key, value);
                }
                debug_map.finish()
            }
            TlaValue::Seq(vec) => {
                let mut debug_list = f.debug_list();
                for elem in vec {
                    debug_list.entry(elem);
                }
                debug_list.finish()
            }
            TlaValue::Literal(s) => write!(f, "\"{s}\""),
            TlaValue::Constant(s) => write!(f, "{s}"),
            TlaValue::Bool(b) => write!(f, "{b}"),
            TlaValue::Int(n) => write!(f, "{n}"),
            TlaValue::Variant { tag, value } => write!(f, "Variant(\"{tag}\", {value:#?})"),
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, CandidType, Debug, Deserialize)]
pub struct TlaConstantAssignment {
    pub constants: BTreeMap<String, TlaValue>,
}

impl TlaConstantAssignment {
    pub fn to_map(&self) -> HashMap<String, String> {
        self.constants
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    }
}

pub trait ToTla {
    fn to_tla_value(&self) -> TlaValue;
}

impl ToTla for TlaValue {
    fn to_tla_value(&self) -> TlaValue {
        self.clone()
    }
}

impl ToTla for Principal {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Literal(self.to_string())
    }
}

impl ToTla for bool {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Bool(*self)
    }
}

impl ToTla for u32 {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Int((*self).into())
    }
}

impl ToTla for u64 {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Int((*self).into())
    }
}

impl ToTla for i32 {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Int((*self).into())
    }
}

impl ToTla for CInt {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Int(self.clone())
    }
}

impl ToTla for Nat {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Int(self.clone().into())
    }
}

impl<K: ToTla, V: ToTla> ToTla for BTreeMap<K, V> {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Function(
            self.iter()
                .map(|(k, v)| (k.to_tla_value(), v.to_tla_value()))
                .collect(),
        )
    }
}

impl<V: ToTla> ToTla for BTreeSet<V> {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Set(self.iter().map(|v| v.to_tla_value()).collect())
    }
}

impl<V: ToTla> ToTla for Vec<V> {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Seq(self.iter().map(|v| v.to_tla_value()).collect())
    }
}

/*
impl<V: ToTla> ToTla for Vec<&V> {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Seq(self.iter().map(|v| v.to_tla_value()).collect())
    }
}
 */

impl ToTla for &str {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Literal(self.to_string())
    }
}

impl ToTla for String {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Literal(self.clone())
    }
}
