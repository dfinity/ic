{ buildGoModule, sources, protobuf, go-protobuf, lib }:
buildGoModule rec {
  pname = "buf";
  inherit (src) version;

  src = sources.buf;

  vendorSha256 = "0axl3r7i38046w22qkqqkmf16bdn8z4q2wrhsbq8sp1q5rdrlqwn";

  # This is to work around the following error in the test-suite:
  #
  # === CONT  TestCompareInsertionPointOutput
  #     protoc_test.go:192:
  #                 Error Trace:    buftesting.go:95
  #                                                         protoc_test.go:192
  #                                                         protoc_test.go:168
  #                 Error:          Received unexpected error:
  #                                 /nix/store/nsqa3i69027yhf398z1ydlr2m7icg0cv-protobuf-3.13.0/bin/protoc returned error: exit status 1 protoc-gen-insertion-point-receiver: program not found or is not executable
  #                                 Please specify a program using absolute path or make sure the program is available in your PATH system variable
  #                                 --insertion-point-receiver_out: protoc-gen-insertion-point-receiver: Plugin failed with status code 1.
  #                 Test:           TestCompareInsertionPointOutput
  # --- FAIL: TestCompareInsertionPointOutput (0.01s)
  doCheck = false; # nativeBuildInputs = [ protobuf go-protobuf ];

  meta = {
    description = "A new way of working with Protocol Buffers.";
    homepage = https://buf.build;
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
