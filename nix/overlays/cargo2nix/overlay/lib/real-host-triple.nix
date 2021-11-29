platform:
let
  cpu = if platform.parsed.cpu.name == "armv6" then "arm" else platform.parsed.cpu.name;
  vendor = platform.parsed.vendor.name;
  kernel = platform.parsed.kernel.name;
  abi = platform.parsed.abi.name;
in
if platform.isWasi or false then
  "${platform.parsed.cpu.name}-wasi"
else {
  "i686-linux" = "i686-unknown-linux-${abi}";
  "x86_64-linux" = "x86_64-unknown-linux-${abi}";
  "armv5tel-linux" = "arm-unknown-linux-${abi}";
  "armv6l-linux" = "arm-unknown-linux-${abi}";
  "armv7a-android" = "armv7-linux-androideabi";
  "armv7l-linux" = "armv7-unknown-linux-${abi}";
  "aarch64-linux" = "aarch64-unknown-linux-${abi}";
  "mips64el-linux" = "mips64el-unknown-linux-${abi}";
  "x86_64-darwin" = "x86_64-apple-darwin";
  "i686-cygwin" = "i686-pc-windows-${abi}";
  "x86_64-cygwin" = "x86_64-pc-windows-${abi}";
  "x86_64-freebsd" = "x86_64-unknown-freebsd";
  "wasm32-emscripten" = "wasm32-unknown-emscripten";
}.${platform.system} or platform.config
