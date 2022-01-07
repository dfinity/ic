pub mod v1 {
    include!(concat!(
        env!("OUT_DIR"),
        "/registry/registry.provisional_whitelist.v1.rs"
    ));
}
