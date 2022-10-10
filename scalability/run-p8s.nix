# TODO: Rewrite this to use docker instead of Nix
# See: https://dfinity.atlassian.net/browse/VER-1941
let
  nixpkgs = builtins.fetchTarball {
    name = "nixpkgs-release-22.05";
    url = "https://github.com/nixos/nixpkgs/archive/ecdafdc9f0cd7af2e316a6ba14f98df537714e5f.tar.gz";
    sha256 = "sha256:0yra4yxlj0fqr7m1rmmfjscrd30li4zkdy0g0wi95fiya9v8nbkd";
  };
  pkgs = import nixpkgs {};
in
pkgs.runCommand "run-prometheus-env" {
  nativeBuildInputs = [
    pkgs.zstd
    pkgs.prometheus
    pkgs.grafana
  ];
  GRAFANA = pkgs.grafana;
} ""
