# TODO: Rewrite this to use docker instead of Nix
# See: https://dfinity.atlassian.net/browse/VER-1941
let
  nixpkgs = builtins.fetchTarball {
    name = "nixpkgs-release-25.05";
    url = "https://github.com/nixos/nixpkgs/archive/a84e756ad67fa42311e2d22cbc8f566ee46a04fd.tar.gz";
    sha256 = "sha256:0q04kkss7ayn9yng6qfg7pgdjc3vzl837s7xqiwypjr3f6x23s9q";
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
