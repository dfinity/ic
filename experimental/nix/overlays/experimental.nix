self: super: {
  experimental = rec {
    wasm-c-api-src = builtins.fetchGit {
      url = "ssh://git@github.com/WebAssembly/wasm-c-api";
      ref = "host-mem";
      rev = "4eba1955fa063676fcd3413c3dbafbfb5bc6bd23";
    };
    wasm-c-api = self.callPackage packages/wasm-c-api/default.nix {
      inherit wasm-c-api-src v8_7_x;
      stdenv = self.llvmPackages_7.stdenv;
    };
    v8_7_x = self.callPackage packages/v8/default.nix {
      inherit wasm-c-api-src;
      stdenv = self.llvmPackages_7.stdenv;
    };
  };
}
