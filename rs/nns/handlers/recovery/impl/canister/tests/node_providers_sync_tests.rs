use crate::tests::{get_current_node_operators, init_pocket_ic, RegistryPreparationArguments};

#[test]
fn node_providers_are_synced_from_registry() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let current_node_operators = get_current_node_operators(&pic, canister);
    assert!(!current_node_operators.is_empty())
}
