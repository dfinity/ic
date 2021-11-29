{ system ? builtins.currentSystem
, pkgs ? import ../../../nix { inherit system; }
, rs ? import ../../../rs { inherit pkgs; }
, tools ? import ../../tools { inherit pkgs rs jobset; }
, jobset ? import ../../../ci/ci.nix { inherit system pkgs; }
}:
pkgs.lib.mkCheckedScript "deployment-test" ./deployment_test.sh {
  buildInputs = [
    pkgs.runtimeShellPackage # the ic-workload-genertor uses `sh -c ulimit -n`.
    rs.ic-workload-generator # we use the ic-workload-generator to e2e test the subnet.
    pkgs.ansible
    pkgs.jq
    pkgs.openssl # Needed to check if TLS is enabled on the nodes.
  ];

  # GIT_DIR overrides the git search location for the .git folder.
  inherit (tools) PROD_SRC;
}
