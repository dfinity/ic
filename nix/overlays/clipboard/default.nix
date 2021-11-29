{ buildGoModule, sources, lib }:
buildGoModule rec {
  pname = "clipboard";
  inherit (src) version;

  src = sources.clipboard;

  vendorSha256 = "0sjjj9z1dhilhpc8pq4154czrb79z9cm044jvn75kxcjv6v5l2m5";

  # This is to work around the following error in the test-suite:
  #
  # === RUN   TestCopyAndPaste
  #     clipboard_test.go:18: exec: "pbcopy": executable file not found in $PATH
  # --- FAIL: TestCopyAndPaste (0.00s)
  # === RUN   TestMultiCopyAndPaste
  #     clipboard_test.go:37: exec: "pbcopy": executable file not found in $PATH
  # --- FAIL: TestMultiCopyAndPaste (0.00s)
  # === RUN   Example
  # --- FAIL: Example (0.00s)
  # got:
  #
  # want:
  # 日本語
  # FAIL
  # FAIL    github.com/atotto/clipboard     0.553s
  # FAIL
  doCheck = false;

  meta = {
    description = "CLI copy/paste to the clipboard";
    homepage = https://github.com/atotto/clipboard;
    license = lib.licenses.bsd3;
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
