use candid::{CandidType, Nat, Principal};
use serde::Deserialize;
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
    Int(Nat),
    Variant { tag: String, value: Box<TlaValue> },
}

impl Display for TlaValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TlaValue::Set(set) => {
                let elements: Vec<_> = set.iter().map(|x| format!("{}", x)).collect();
                write!(f, "{{{}}}", elements.join(", "))
            }
            TlaValue::Record(map) => {
                let elements: Vec<_> = map
                    .iter()
                    .map(|(k, v)| format!("{} |-> {}", k, v))
                    .collect();
                write!(f, "[{}]", elements.join(", "))
            }
            TlaValue::Function(map) => {
                let elements: Vec<_> = map.iter().map(|(k, v)| format!("{} :> {}", k, v)).collect();
                write!(f, "({})", elements.join(" @@ "))
            }
            TlaValue::Seq(vec) => {
                let elements: Vec<_> = vec.iter().map(|x| format!("{}", x)).collect();
                write!(f, "<<{}>>", elements.join(", "))
            }
            TlaValue::Literal(s) => write!(f, "\"{}\"", s),
            TlaValue::Constant(s) => write!(f, "{}", s),
            TlaValue::Bool(b) => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            // Candid likes to pretty print its numbers
            TlaValue::Int(i) => write!(f, "{}", format!("{}", i).replace("_", "")),
            TlaValue::Variant { tag, value } => write!(f, "Variant(\"{}\", {})", tag, value),
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
                    debug_map.entry(&format!("\"{}\"", key), value);
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
            TlaValue::Literal(s) => write!(f, "\"{}\"", s),
            TlaValue::Constant(s) => write!(f, "{}", s),
            TlaValue::Bool(b) => write!(f, "{}", b),
            TlaValue::Int(n) => write!(f, "{}", n),
            TlaValue::Variant { tag, value } => write!(f, "Variant(\"{}\", {:#?})", tag, value),
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize, Debug)]
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

impl ToTla for Nat {
    fn to_tla_value(&self) -> TlaValue {
        TlaValue::Int(self.clone())
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
