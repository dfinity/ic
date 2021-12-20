{ config ? {}
, system ? builtins.currentSystem
, pkgs ? import ../../nix { inherit config system; }
, rs ? import ../../rs { inherit pkgs; }
}:
let
  lib = pkgs.lib;

  # Here we wrap the ic-test-bin in the environment it needs,
  # with replica and orchestrator on the path, and all NNS canisters set up
  # This allows you to run the replica with
  #
  # nix run -f tests/ic-ref-test ic-test-bin -c ic-test-bin
  #
  # and then interact with it interactively
  ic-test-bin = pkgs.runCommandNoCC "ic-test-bin"
    { buildInputs = [ pkgs.makeWrapper ]; }
    ''
      mkdir $out
      makeWrapper ${rs.ic-test-bin}/bin/ic-test-bin $out/bin/ic-test-bin \
        --prefix PATH : ${rs.ic-replica-unwrapped}/bin \
        --prefix PATH : ${rs.orchestrator-unwrapped}/bin \
    '';

  drv = { ver, ic-ref, use-app-subnet }:
    pkgs.lib.linuxOnly (
      pkgs.stdenvNoCC.mkDerivation {
        name = "ic-ref-test-${ver}";
        src = pkgs.lib.noNixFiles (pkgs.lib.gitOnlySource ./.);
        buildInputs = [
          ic-test-bin
          ic-ref
          pkgs.which
          pkgs.netcat
        ];
        USE_APP_SUBNET = if use-app-subnet then "true" else "false";
        buildPhase = ''
          patchShebangs ./run
          # makes haskell happier on hydra
          export LANG=C.UTF-8
          ./run
        '';
        installPhase = ''
          mkdir -p $out
          cp -v report.html $out || true

          mkdir -p $out/nix-support
            echo "report test-results $out report.html" >> $out/nix-support/hydra-build-products
        '';
      }
    )
  ;

  # select sources from `/nix/sources.json` that are ic-ref sources
  ic-ref-srcs = lib.lists.filter
    (name: lib.strings.hasPrefix "ic-ref-" name)
    (builtins.attrNames pkgs.sources);

  # two jobs per version: one on a system subnet and one on an app subnet
  mk-ic-ref-jobs = name:
    let
      ver = lib.strings.removePrefix "ic-ref-" name;
      src = pkgs.sources."${name}";
      ic-ref = (import src { inherit system; }).ic-ref;
    in
      [
        { name = "${ver}"; value = drv { inherit ver ic-ref; use-app-subnet = false; }; }
        { name = "${ver}-use-app-subnet"; value = drv { inherit ver ic-ref; use-app-subnet = true; }; }
      ];

  jobs = builtins.listToAttrs (lib.lists.concatMap mk-ic-ref-jobs ic-ref-srcs);
in
jobs // { inherit ic-test-bin; }
