pub mod v1 {
    include!(concat!(
        env!("OUT_DIR"),
        "/registry/registry.conversion_rate.v1.rs"
    ));
}
