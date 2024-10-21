use std::marker::PhantomData;

use crate::{
    access_control::{AccessLevel, ResolveAccessLevel},
    types::{OutputConfig, OutputRuleMetadata},
};

/// Trait for formatting confidential data based on access levels
pub trait ConfidentialityFormatting {
    type Input: Clone;

    fn format(&self, value: &Self::Input) -> Result<Self::Input, ConfidentialFormatterError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ConfidentialFormatterError {
    #[error("Access denied")]
    _AccessDenied,
}

/// A generic confidentiality formatter for various data types
pub struct ConfidentialityFormatter<A, T> {
    access_resolver: A,
    phantom: PhantomData<T>,
}

impl<A, T> ConfidentialityFormatter<A, T> {
    pub fn new(access_resolver: A) -> Self {
        Self {
            access_resolver,
            phantom: PhantomData,
        }
    }
}

impl<A: ResolveAccessLevel> ConfidentialityFormatting
    for ConfidentialityFormatter<A, OutputConfig>
{
    type Input = OutputConfig;

    fn format(&self, config: &OutputConfig) -> Result<OutputConfig, ConfidentialFormatterError> {
        let mut config = config.clone();
        if self.access_resolver.get_access_level() == AccessLevel::RestrictedRead {
            config.rules.iter_mut().for_each(|rule| {
                if rule.disclosed_at.is_none() {
                    rule.description = None;
                    rule.rule_raw = None;
                }
            });
        }
        Ok(config)
    }
}

impl<A: ResolveAccessLevel> ConfidentialityFormatting
    for ConfidentialityFormatter<A, OutputRuleMetadata>
{
    type Input = OutputRuleMetadata;

    fn format(
        &self,
        rule: &OutputRuleMetadata,
    ) -> Result<OutputRuleMetadata, ConfidentialFormatterError> {
        let mut rule = rule.clone();
        if self.access_resolver.get_access_level() == AccessLevel::RestrictedRead
            && rule.disclosed_at.is_none()
        {
            rule.description = None;
            rule.rule_raw = None;
        }
        Ok(rule)
    }
}

/// Factory for creating confidentiality formatters
pub struct ConfidentialityFormatterFactory<A> {
    access_resolver: A,
}

impl<A: ResolveAccessLevel + Clone> ConfidentialityFormatterFactory<A> {
    pub fn new(access_resolver: A) -> Self {
        Self { access_resolver }
    }

    /// Create a confidentiality formatter for OutputConfig
    pub fn create_config_formatter(&self) -> ConfidentialityFormatter<A, OutputConfig> {
        ConfidentialityFormatter::new(self.access_resolver.clone())
    }

    /// Create a confidentiality formatter for OutputRuleMetadata
    pub fn create_rule_formatter(&self) -> ConfidentialityFormatter<A, OutputRuleMetadata> {
        ConfidentialityFormatter::new(self.access_resolver.clone())
    }
}
