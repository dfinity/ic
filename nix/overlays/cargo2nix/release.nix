{ nixpkgs ? builtins.fetchTarball {
    url = https://github.com/NixOS/nixpkgs/archive/47b551c6a854a049045455f8ab1b8750e7b00625.tar.gz;
    sha256 = "0p0p6gf3kimcan4jgb4im3plm3yw68da09ywmyzhak8h64sgy4kg";
  }
, nixpkgsMozilla ? builtins.fetchTarball {
    url = https://github.com/mozilla/nixpkgs-mozilla/archive/50bae918794d3c283aeb335b209efd71e75e3954.tar.gz;
    sha256 = "07b7hgq5awhddcii88y43d38lncqq9c8b2px4p93r5l7z0phv89d";
  }
, system ? builtins.currentSystem
, overlays ? []
, crossSystem ? null
,
}:
let
  # 1. Setup nixpkgs with nixpkgs-mozilla overlay and cargo2nix overlay.
  pkgs = import nixpkgs {
    inherit system crossSystem;
    overlays =
      let
        rustOverlay = import "${nixpkgsMozilla}/rust-overlay.nix";
        cargo2nixOverlay = import ./overlay;
      in
        [ cargo2nixOverlay rustOverlay ] ++ overlays;
  };

  # 2. Builds the rust package set, which contains all crates in your cargo workspace's dependency graph.
  # `makePackageSet'` accepts the following arguments:
  # - `packageFun` (required): The generated `Cargo.nix` file, which returns the whole dependency graph.
  # - `rustChannel` (required): The Rust channel used to build the package set.
  # - `packageOverrides` (optional):
  #     A function taking a package set and returning a list of overrides.
  #     Overrides are introduced to provide native inputs to build the crates generated in `Cargo.nix`.
  #     See `overlay/lib/overrides.nix` on how to create overrides and `overlay/overrides.nix` for a list of predefined overrides.
  #     Most of the time, you can just use `overrides.all`. You can hand-pick overrides later if your build becomes too slow.
  # - `localPatterns` (optional):
  #     A list of regular expressions that specify what should be included in the sources of your workspace's crates.
  #     The expressions are relative to each crate's manifest directory.
  #     This argument is optional and defaults to include the `src` directory and all `toml` files at the root of the manifest directory.
  # - `rootFeatures` (optional):
  #     A list of activated features on your workspace's crates.
  #     Each feature should be of the form `<crate_name>[/<feature>]`.
  #     If `/<feature>` is omitted, the crate is activated with no default features.
  #     The default behavior is to activate all crates with default features.
  # - `fetchCrateAlternativeRegistry` (optional): A fetcher for crates on alternative registries.
  # - `release` (optional): Whether to enable release mode (equivalent to `cargo build --release`), defaults to `true`.
  # - `hostPlatformCpu` (optional):
  #     Equivalent to rust's target-cpu codegen option. If specified "-Ctarget-cpu=<value>" will be added to the set of rust
  #     flags used for compilation of the package set.
  # - `hostPlatformFeatures` (optional):
  #     Equivalent to rust's target-feature codegen option. If specified "-Ctarget-feature=<values>" will be added to the set of rust
  #     flags used for compilation of the package set. The value should be a list of the features to be turned on, without the leading "+",
  #     e.g. `[ "aes" "sse2" "ssse3" "sse4.1" ]`.  They will be prefixed with a "+", and comma delimited before passing through to rust.
  #     Crates that check for CPU features such as the `aes` crate will be evaluated against this argument.
  rustPkgs = pkgs.pkgsStatic.rustBuilder.makePackageSet' {
    rustChannel = "1.41.0";
    packageFun = import ./Cargo.nix;
    packageOverrides = pkgs: with pkgs.rustBuilder.overrides; [
      libgit2-sys
      openssl-sys
      (
        pkgs.rustBuilder.rustLib.makeOverride {
          name = "curl-sys";
          overrideAttrs = drv: {
            propagatedBuildInputs = drv.propagatedBuildInputs ++ [
              (pkgs.curl.override { gssSupport = false; })
            ];
          };
        }
      )
    ];
    localPatterns = [ ''^(src|tests|templates)(/.*)?'' ''[^/]*\.(rs|toml)$'' ];
  };
in
(rustPkgs.workspace.cargo2nix {}).overrideDerivation (
  drv: {
    nativeBuildInputs = drv.nativeBuildInputs ++ [ pkgs.nukeReferences ];
    propagatedBuildInputs = [];
    propagatedNativeBuildInputs = [];
    postInstall = ''
      # openssl-sys puts some absolute paths in the binary, but we don't need them
      nuke-refs $out/bin/cargo2nix
    '';
  }
)
