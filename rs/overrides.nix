self: with self.rustBuilder.rustLib;

let
  protosFrom = dir: self.lib.sourceFilesBySuffices (self.lib.gitOnlySource dir) [ ".proto" ];
in

  # If you need to change the build process for a crate **ONLY** in Nix builds, make the change here.
  #
  # If you're not sure whether your change qualifies, please modify crate-environment.nix instead.
[
  (
    makeOverride {
      name = "lifeline";
      overrideAttrs = oldAttrs: {
        # the nix build needs to install the wasm file in the correct place.
        postInstall = ''
          mkdir -p $out/bin
          cp -r gen/lifeline.wasm $out/bin/lifeline.wasm
        '';
      };
    }
  )
  (
    makeOverride {
      name = "wait-timeout";
      overrideAttrs = _: {
        # This crate builds an exe called `sleep` which takes milliseconds as an argument rather than whole seconds (like bash).
        # We don't want it to be in the environment during E2E tests.
        postInstall = ''
          rm -fv $out/bin/sleep
        '';
      };
    }
  )
  (
    makeOverride {
      name = "lmdb-rkv-sys";
      overrideArgs = _: {
        doDoc = false;
      };
    }
  )
  (
    makeOverride {
      # cargo2nix-ese for "apply to crates in the workspace only"
      registry = "file://local-registry";

      overrideAttrs = _: {
        # include paths, for crates that need to access protobuf files from other crates
        IC_BASE_TYPES_PROTO_INCLUDES = protosFrom ./types/base_types/proto;
        IC_NNS_COMMON_PROTO_INCLUDES = protosFrom ./nns/common/proto;
        IC_PROTOBUF_PROTO_INCLUDES = protosFrom ./protobuf/def;
        IC_LEDGER_PROTO_INCLUDES = protosFrom ./rosetta-api/ledger_canister/proto;
        REGISTRY_TRANSPORT_PROTO_INCLUDES = protosFrom ./registry/transport/proto;

        # interface files. currently only used by lifeline, but set here in case other crates need them
        ROOT_DID = ./nns/handlers/root/canister/root.did;
        GOVERNANCE_DID = ./nns/governance/canister/governance.did;
      };
    }
  )
]
