use crate::types::{CanisterEndpoint, CanisterEndpoints};
use anyhow::{Error, Result};
use candid::types::{FuncMode, Function, TypeInner};
use candid_parser::utils::CandidSource;
use std::path::PathBuf;

#[cfg(test)]
mod tests;

pub struct CandidParser {
    path: PathBuf,
}

impl CandidParser {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn parse(&self) -> Result<CanisterEndpoints> {
        let (_, maybe_actor) = CandidSource::File(&self.path).load()?;

        let maybe_class =
            maybe_actor.ok_or_else(|| Error::msg("Top-level actor definition not found"))?;

        let maybe_service = match maybe_class.as_ref() {
            TypeInner::Class(_, class) => class,
            _ => return Err(Error::msg("Top-level class definition not found")),
        };

        let maybe_functions = match maybe_service.as_ref() {
            TypeInner::Service(maybe_functions) => maybe_functions,
            _ => return Err(Error::msg("Top-level service definition not found")),
        };

        let functions = maybe_functions
            .iter()
            .filter_map(|(name, maybe_function)| {
                if let TypeInner::Func(Function { modes, .. }) = maybe_function.as_ref() {
                    if modes.contains(&FuncMode::Query) {
                        Some(CanisterEndpoint::Query(name.to_string()))
                    } else {
                        Some(CanisterEndpoint::Update(name.to_string()))
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(functions)
    }
}
