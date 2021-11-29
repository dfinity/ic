{ system ? builtins.currentSystem
, baseJobs ? null
, jobset ? import ../../ci/ci.nix { inherit system pkgs; }
, pkgs ? import ../../nix { inherit system; }
, rs ? import ../../rs { inherit pkgs; }
, tools ? import ../tools { inherit pkgs rs jobset; }
}:
let
  # NixOS systems and tests can only be instantiated for and build on Linux.
  pkgsLinux = pkgs.pkgsForSystem.x86_64-linux;

  inherit (pkgs) lib;
in
rec {
  # These just builds the test script on CI to validate that it builds.
  # This doesn't run the actual test in CI [which must run on CD].
  deployment-test-script = import ./deployment { inherit pkgs rs tools jobset; };
}
