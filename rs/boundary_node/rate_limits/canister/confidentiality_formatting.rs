use mockall::automock;

use crate::types::{OutputConfig, OutputRuleMetadata};

/// Trait for formatting confidential data based on access levels
#[automock(type Input = OutputConfig;)]
pub trait ConfidentialityFormatting<Input = OutputConfig> {
    type Input: Clone;

    fn format(&self, value: &Self::Input) -> Self::Input;
}

pub struct ConfigConfidentialityFormatter;

pub struct RuleConfidentialityFormatter;

impl ConfidentialityFormatting for ConfigConfidentialityFormatter {
    type Input = OutputConfig;

    fn format(&self, config: &OutputConfig) -> OutputConfig {
        let mut config = config.clone();
        // Redact output of undisclosed rules
        config.rules.iter_mut().for_each(|rule| {
            if rule.disclosed_at.is_none() {
                rule.description = None;
                rule.rule_raw = None;
            }
        });
        config
    }
}

impl ConfidentialityFormatting for RuleConfidentialityFormatter {
    type Input = OutputRuleMetadata;

    fn format(&self, rule: &OutputRuleMetadata) -> OutputRuleMetadata {
        let mut rule = rule.clone();
        // Redact output of undisclosed rules
        if rule.disclosed_at.is_none() {
            rule.description = None;
            rule.rule_raw = None;
        }
        rule
    }
}
