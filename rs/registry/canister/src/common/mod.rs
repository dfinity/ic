pub const LOG_PREFIX: &str = "[Registry] ";

#[cfg(test)]
pub mod test_helpers;

#[cfg(test)]
pub mod registry_builder_helpers {
    use test_registry_builder::registry_builder::CompliantRegistry;

    use crate::registry::Registry;

    pub fn over_compliant_registry<F, R>(compliant_registry: &CompliantRegistry, f: F) -> R
    where
        F: FnOnce(&mut Registry) -> R,
    {
        let mut registry = Registry::new();

        registry.maybe_apply_mutation_internal(compliant_registry.mutations());

        f(&mut registry)
    }
}
