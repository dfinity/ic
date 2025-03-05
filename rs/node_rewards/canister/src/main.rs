use ic_cdk::query;

fn main() {
    println!("Hello, world!");
}

#[query]
fn get_hello() -> String {
    "Hello, world!".to_string()
}

#[cfg(test)]
mod tests {
    use candid_parser::utils::{service_equal, CandidSource};
    #[test]
    fn test_implemented_interface_matches_declared_interface_exactly() {
        let declared_interface = CandidSource::Text(include_str!("../node-rewards-canister.did"));

        // The line below generates did types and service definition from the
        // methods annotated with `candid_method` above. The definition is then
        // obtained with `__export_service()`.
        candid::export_service!();
        let implemented_interface_str = __export_service();
        let implemented_interface = CandidSource::Text(&implemented_interface_str);

        let result = service_equal(declared_interface, implemented_interface);
        assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
    }
}
