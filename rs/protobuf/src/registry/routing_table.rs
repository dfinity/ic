pub mod v1 {
    include!(concat!(
        env!("OUT_DIR"),
        "/registry/registry.routing_table.v1.rs"
    ));
}
