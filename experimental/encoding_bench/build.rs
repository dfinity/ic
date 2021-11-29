use capnpc;

const PATH_KEY: &str = "PATH";
const LOCAL_PATH: &str = "/usr/local/bin";

fn main() {
    // XXX: Explicitly add path to work around missing capnp in nix-environment.
    let path = std::env::vars().find(|(k, _)| k == PATH_KEY).unwrap();
    std::env::set_var(PATH_KEY, format!("{}:{}", path.1, LOCAL_PATH));

    capnpc::CompilerCommand::new()
        .file("capnproto/ingress.capnp")
        .run()
        .expect("compiling ingress schema");

    prost_build::compile_protos(&["proto/ingress_wire.proto"], &["proto"]).unwrap();
}
