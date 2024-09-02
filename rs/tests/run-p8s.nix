# TODO: Rewrite this to use docker instead of Nix
# See: https://dfinity.atlassian.net/browse/VER-1941
let
  nixpkgs = builtins.fetchTarball {
    name = "nixpkgs-release-22.11";
    url = "https://github.com/nixos/nixpkgs/archive/6047d0269b0006756103db57bd5e47b8c4b6381b.tar.gz";
    sha256 = "sha256:0hsvb1z8nx9alrhix16bcdjnsa6bv39n691vw8bd1ikvbri4r8yv";
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
