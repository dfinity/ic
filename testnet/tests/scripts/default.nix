{ pkgs ? import ../../../nix { inherit system; }
, system ? builtins.currentSystem
}:
let
  python3-packages = python-packages: with python-packages; [
    ansible
    pyyaml
  ];
  python3-with-packages = pkgs.python3.withPackages python3-packages;
in
pkgs.mkCiShell {
  buildInputs = [
    python3-with-packages
    pkgs.ansible # for ansible-inventory
    pkgs.bc
    pkgs.coreutils
    pkgs.curl
    pkgs.dfx
    pkgs.findutils # for xargs
    pkgs.git
    pkgs.gnugrep
    pkgs.gnutar
    pkgs.gzip # and unzip IC tarballs.
    pkgs.idl2json # to parse dfx result
    pkgs.jq
    pkgs.openssh # Ansible uses ssh to connect to the nodes.
    pkgs.openssl # Needed to check if TLS is enabled on the nodes.
    pkgs.procps # Needed for GNU ps to kill processes
    pkgs.rsync
    pkgs.rclone
    pkgs.runtimeShellPackage # the ic-workload-genertor uses `sh -c ulimit -n`.
    pkgs.sed
    pkgs.which

    pkgs.csmith
    pkgs.gcc
    pkgs.llvmPackages_10.lld
    pkgs.llvmPackages_10.clang-unwrapped
    pkgs.llvmPackages_10.libcxx

    pkgs.diffutils
  ];

  # needed by tests/test_modules/wasm-generator/wasm-generator.sh
  CSMITH_INCLUDE = "${pkgs.csmith}/include/${pkgs.csmith.name}";
  LIBC_INCLUDE = "${pkgs.lib.getDev pkgs.stdenv.cc.libc}/include";

  ANSIBLE_INVENTORY_PREPEND_PATH = pkgs.lib.makeBinPath [
    (
      pkgs.python3.withPackages (
        ps: [
          ps.pyyaml
          ps.ansible
        ]
      )
    )
  ];
}
