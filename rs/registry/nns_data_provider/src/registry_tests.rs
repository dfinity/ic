use super::*;

#[test]
#[should_panic]
fn empty_urls_panics() {
    RegistryCanister::new(vec![]);
}
