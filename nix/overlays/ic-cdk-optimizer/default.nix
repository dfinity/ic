{ naersk, sources, cmake, runCommand }:

naersk.buildPackage {
  src = runCommand "ic-cdk-optimizer-src" {} ''
    mkdir -p $out
    cd $out
    tar xzvf ${sources.ic-cdk-optimizer} --strip-components=1
  '';
  override = attrs: {
    CMAKE = "${cmake}/bin/cmake";
    # if SDKROOT is set, the `cc` crate tries to execute `xcrun` and silently fails.
    postConfigure = ''
      unset SDKROOT
    '';
  };
}
