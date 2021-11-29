{ pkgs ? import ../nix { inherit system; }, system ? builtins.currentSystem }:
pkgs.mkCiShell {
  buildInputs = [
    (pkgs.python3.withPackages (ps: with ps; [ cbor GitPython paramiko requests pyyaml ansible ]))
    pkgs.ansible
    pkgs.ansible-lint
    pkgs.bc # needed for calculations in the p2p testcases
    pkgs.cbor-diag # handy for parsing the output of the /api/v2/status replica http endpoint
    pkgs.clipboard
    pkgs.dfx
    pkgs.gitAndTools.hub
    pkgs.idl2json # to parse dfx result
    pkgs.jq
    pkgs.openssl
    pkgs.openssh # needed by commands that alter a single machine (stress)
    pkgs.prometheus-alertmanager
    pkgs.protobufc
    pkgs.sshpass
    pkgs.opensc # Needed for pkcs11-tool
  ];

  ANSIBLE_INVENTORY_PREPEND_PATH = pkgs.lib.makeBinPath
    [ (pkgs.python3.withPackages (ps: [ ps.pyyaml ps.ansible ])) ];
}
