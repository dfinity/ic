use prost_build::Config;
use std::env;

// Build protos using prost_build.
fn main() {
    let proto_file = "proto/ic_nns_handler_root/pb/v1/root.proto";

    // On CI we get the protobufs from common from nix, through a var set
    // on overrides.nix, but locally we can just refer to the common crate
    // through relative paths.
    let common_proto_dir =
        env::var("IC_NNS_COMMON_PROTO_INCLUDES").unwrap_or_else(|_| "../../common/proto".into());

    let base_types_proto_dir = match env::var("IC_BASE_TYPES_PROTO_INCLUDES") {
        Ok(dir) => dir,
        Err(_) => "../../../types/base_types/proto".into(),
    };

    let mut config = Config::new();
    config.extern_path(".ic_nns_common.pb.v1", "::ic-nns-common::pb::v1");
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    println!("cargo:rerun-if-changed={}", proto_file);
    config
        .compile_protos(
            &[proto_file],
            &["proto", &common_proto_dir, &base_types_proto_dir],
        )
        .unwrap();
}
