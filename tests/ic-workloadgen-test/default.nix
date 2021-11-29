{ config ? {}
, system ? builtins.currentSystem
, pkgs ? import ../../nix { inherit config system; }
, verbose ? false
, ic-run-test ? ../ic-run-test
}:
let
  lib = pkgs.lib;
  mkWorkloadgenTest = name: cmd:
    let
      # The tests are flaky on Darwin so we only run them on Linux.
      mk = LOGLEVEL: pkgs.lib.linuxOnly (
        pkgs.runCommandNoCC
          ("ic-workloadgen-test-${name}" + lib.optionalString (LOGLEVEL != "") "-${LOGLEVEL}")
          {
            buildInputs = [
              pkgs.dfinity-rs.ic-starter
              pkgs.dfinity-rs.ic-replica
              pkgs.dfinity-rs.ic-prep
              pkgs.dfinity-rs.ic-workload-generator
              pkgs.netcat
            ];
            inherit LOGLEVEL;
          } ''
          # makes haskell happier on hydra
          export LANG=C.UTF-8

          extra_args=( )

          if [ -n "$LOGLEVEL" ];
          then
              extra_args+=( "--loglevel" "$LOGLEVEL" )
          fi

          echo 'Running workload test: ${name}'
          ${pkgs.bash}/bin/bash ${ic-run-test} -- ${cmd}
          touch $out
        ''
      );
    in
      { default = mk ""; } // lib.optionalAttrs verbose { verbose = mk "trace"; };
in

pkgs.lib.mapAttrs mkWorkloadgenTest {
  rps-mode-update-calls =
    ''"ic-workload-generator \"\$IC_URI\" -u -r 1 -n 1;"'';

  rps-mode-query-calls =
    ''"ic-workload-generator \"\$IC_URI\" -r 1 -n 1;"'';
}
