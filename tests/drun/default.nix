{ config ? {}
, system ? builtins.currentSystem
, pkgs ? import ../../nix { inherit config system; }
, rs ? import ../../rs { inherit pkgs; }
}:
pkgs.stdenvNoCC.mkDerivation {
  name = "drun-test";
  src = pkgs.lib.noNixFiles (pkgs.lib.gitOnlySource ./.);
  buildInputs = [
    pkgs.wabt
    rs.drun-unwrapped
  ];
  buildPhase = ''
    patchShebangs ./run
    ./run
  '';
  installPhase = ''
    touch $out
  '';
}
