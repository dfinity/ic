{ system ? builtins.currentSystem
, pkgs ? import ../../nix { inherit system; }
, rs ? import ../../rs { inherit pkgs; }
, jobset ? import ../../ci/ci.nix { inherit system pkgs; }
}:
let
  testnet_install_buildInputs = [
    pkgs.coreutils # Ansible uses `uname` among other core utilities.
    pkgs.ansible # We deploy the IC using ansible.
    pkgs.gnutar # Ansible needs to untar,
    pkgs.gzip # and unzip IC tarballs.
    pkgs.jq # To parse the ansible inventory.
    pkgs.openssh # Ansible uses ssh to connect to the nodes.
    pkgs.runtimeShellPackage # the ic-workload-genertor uses `sh -c ulimit -n`.
  ];
in
rec {
  # This is the `testnet` directory suitable for use with ansible. It's used by
  # various jobs that `cd` to it before executing ansible commands.
  #
  # It only includes files tracked in git and excludes files that are not used
  # by ansible like `*.nix`, `tests/*`, `docs/*` and `tools/*`. This reduces the
  # number of rebuilds when any of those excluded files are changed.
  PROD_SRC =
    let
      src = lib.noNixFiles (lib.gitOnlySource ../.);
      inherit (pkgs) lib;
    in
      lib.cleanSourceWith {
        name = "testnet";
        inherit src;
        filter = path: type:
          let
            relPath = lib.removePrefix (toString src.origSrc + "/") (toString path);
            notDir = dir: !((relPath == dir && type == "directory") || lib.hasPrefix "${dir}/" relPath);
          in
            notDir "tests" && notDir "docs" && notDir "tools";
      };

  IC_NNS_BUNDLE = jobset.dfinity.rs.ic-nns-bundle-release.x86_64-linux;
}
