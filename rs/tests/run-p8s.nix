# TODO: Rewrite this to use docker instead of Nix
# See: https://dfinity.atlassian.net/browse/VER-1941
let
  nixpkgs = builtins.fetchTarball {
    name = "nixpkgs-release-24.05";
    url = "https://github.com/nixos/nixpkgs/archive/9db4f92627fe77165cf6dbb1fbad1c869db93023.tar.gz";
    sha256 = "sha256:17pc791yicjg56dw3yzqbmjq28k15kvw11lcpy632l09r1v5h30w";
  };
  pkgs = import nixpkgs { };
in
pkgs.runCommand "run-prometheus-env"
{
  nativeBuildInputs = [
    pkgs.zstd
    pkgs.prometheus
    pkgs.grafana
  ];
  GRAFANA = pkgs.grafana;
} ""
