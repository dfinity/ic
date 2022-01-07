pub mod v1 {
    include!(concat!(
        env!("OUT_DIR"),
        "/registry/registry.firewall.v1.rs"
    ));
}
