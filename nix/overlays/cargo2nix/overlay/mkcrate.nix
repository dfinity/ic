{ cargo
, rustc
, lib
, pkgs
, buildPackages
, rustLib
, stdenv
,
}:
{ release
, # Compiling in release mode?
  name
, version
, registry
, src
, features ? []
, dependencies ? {}
, devDependencies ? {}
, buildDependencies ? {}
, compileMode ? "build"
, doInstallCheck ? compileMode != "build"
, doDoc ? compileMode == "build"
, profile
, meta ? {}
, rustcflags ? []
, rustcBuildFlags ? []
, hostPlatformCpu ? null
, hostPlatformFeatures ? []
, NIX_DEBUG ? 0
, # flags sent to the test executables, based on the crate name.
  #  `cargo test ... -- <here come the flags>`
  extraTestFlags ? (_: [])
,
}:
with builtins; with lib;
let
  inherit (rustLib) realHostTriple decideProfile;

  wrapper = exename: rustLib.wrapRustc { inherit rustc exename; };

  ccForBuild = "${buildPackages.stdenv.cc}/bin/${buildPackages.stdenv.cc.targetPrefix}cc";
  cxxForBuild = "${buildPackages.stdenv.cc}/bin/${buildPackages.stdenv.cc.targetPrefix}c++";
  targetPrefix = stdenv.cc.targetPrefix;
  cc = stdenv.cc;
  ccForHost = "${cc}/bin/${targetPrefix}cc";
  cxxForHost = "${cc}/bin/${targetPrefix}c++";
  host-triple = realHostTriple stdenv.hostPlatform;
  depMapToList = deps:
    flatten
      (
        sort (a: b: elemAt a 0 < elemAt b 0)
          (mapAttrsToList (name: value: [ name "${value}" ]) deps)
      );
  hasDefaultFeature = elem "default" features;
  featuresWithoutDefault =
    if hasDefaultFeature
    then filter (feature: feature != "default") features
    else features;
  buildMode = {
    "test" = "--tests";
    "bench" = "--benches";
  }.${compileMode} or "";
  featuresArg =
    if featuresWithoutDefault == []
    then []
    else [ "--features" (concatStringsSep "," featuresWithoutDefault) ];
  commonCargoArgs = concatStringsSep " "
    (
      [ "$CARGO_VERBOSE" ]
      ++ optional release "--release"
      ++ featuresArg
      ++ optional (!hasDefaultFeature) "--no-default-features"
    );
  needDevDependencies = compileMode == "test" || compileMode == "bench";
  preserveBench =
    if registry == "file://local-registry"
    then ".bench"
    else "null";

  inherit
    (({ right, wrong }: { runtimeDependencies = right; buildtimeDependencies = wrong; })
      (
        partition (drv: drv.stdenv.hostPlatform == stdenv.hostPlatform)
          (
            concatLists [
              (attrValues dependencies)
              (optionals needDevDependencies (attrValues devDependencies))
              (attrValues buildDependencies)
            ]
          )
      ))
    runtimeDependencies buildtimeDependencies
    ;

  dependencyGraph = crate: builtins.listToAttrs (
    builtins.genericClosure {
      startSet = makeKvs crate;
      operator = crate: makeKvs crate.value;
    }
  );

  makeKvs = parent: map
    (
      crate: rec {
        key = "${crate.name}-${crate.version}";
        name = key;
        value = crate;
      }
    )
    (builtins.attrValues (parent.dependencies // parent.devDependencies));

  maybeSelfLib = (dependencyGraph { inherit dependencies devDependencies; })."${name}-${version}" or null;

  drvAttrs = {
    inherit NIX_DEBUG;
    name = "${name}-${version}${optionalString (compileMode != "build") "-${compileMode}"}";
    inherit src version meta;
    inherit doDoc needDevDependencies;
    buildMode = if release then "release" else "debug";
    propagatedBuildInputs = lib.unique (concatMap (drv: drv.propagatedBuildInputs) runtimeDependencies);
    nativeBuildInputs = [ cargo ] ++ buildtimeDependencies;

    RUSTC = "${wrapper "rustc"}/bin/rustc";
    RUSTDOC = "${wrapper "rustdoc"}/bin/rustdoc";

    # allows easier overriding of the cargo invocation (to run clippy and so on)
    CARGO_BUILD_TARGET = host-triple;

    # https://github.com/tpoechtrager/cctools-port/blob/43f32a4c61b5ba7fde011e816136c550b1b3146f/cctools/ld64/src/ld/Options.cpp#L4519
    ZERO_AR_DATE = 1;

    # uncomment to print linker invocation and output. useful for debugging
    # RUSTC_LOG = "rustc_codegen_ssa::back::link=info";

    depsBuildBuild =
      let
        inherit (buildPackages.buildPackages) stdenv jq remarshal;
      in
        [ stdenv.cc jq remarshal ];

    stripDebugList = [ "bin" ];

    passthru = {
      inherit
        name
        version
        registry
        dependencies
        devDependencies
        buildDependencies
        features
        ;
      shell = pkgs.mkShell (removeAttrs drvAttrs [ "src" ]);
    };

    dependencies = depMapToList dependencies;
    buildDependencies = depMapToList buildDependencies;
    devDependencies = depMapToList (optionalAttrs needDevDependencies devDependencies);

    selfLib =
      if !needDevDependencies || maybeSelfLib == null
      then null
      else "${maybeSelfLib}/lib";

    extraRustcFlags =
      optionals (hostPlatformCpu != null) ([ ("-Ctarget-cpu=" + hostPlatformCpu) ]) ++ optionals (hostPlatformFeatures != []) [ ("-Ctarget-feature=" + (concatMapStringsSep "," (feature: "+" + feature) hostPlatformFeatures)) ] ++ rustcflags;

    extraRustcBuildFlags = rustcBuildFlags;

    # HACK: 2019-08-01: wasm32-wasi always uses `wasm-ld`
    configureCargo = ''
      mkdir -p .cargo
      # Remove any existing lto flags. We'll do lto for wasm target only.
      test -f .cargo/config && sed -i 's/^.*lto *=.*$//' .cargo/config
      cat >> .cargo/config <<'EOF'
      
      [target."${realHostTriple stdenv.buildPlatform}"]
      linker = "${ccForBuild}"
    '' + optionalString (stdenv.buildPlatform != stdenv.hostPlatform && !(stdenv.hostPlatform.isWasi or false)) ''
      [target."${host-triple}"]
      linker = "${ccForHost}"
    '' + optionalString (host-triple == "wasm32-unknown-unknown") ''
      rustflags = ["-C", "embed-bitcode=yes", "-C", "lto=yes", "-C", "opt-level=z"]
    '' + ''
      EOF
    '';

    manifestPatch = toJSON {
      features = genAttrs features (_: []);
      profile.${ decideProfile compileMode release } = profile;
    };

    overrideCargoManifest = ''
      echo "[[package]]" > Cargo.lock
      echo name = \"${name}\" >> Cargo.lock
      echo version = \"${version}\" >> Cargo.lock
      echo source = \"registry+${registry}\" >> Cargo.lock
      mv Cargo.toml Cargo.original.toml
      remarshal -if toml -of json Cargo.original.toml \
        | jq "{ package: .package
              , lib: .lib
              , bin: .bin
              , test: .test
              , example: .example
              , bench: ${preserveBench}
              } + $manifestPatch" \
        | remarshal -if json -of toml > Cargo.toml
    '';

    configurePhase =
      ''
        runHook preConfigure
        runHook configureCargo
        runHook postConfigure
      '';

    runCargo = ''
      (
        set -euo pipefail
        if (( NIX_DEBUG >= 1 )); then
          set -x
        fi
        env \
          "CC_${stdenv.buildPlatform.config}"="${ccForBuild}" \
          "CXX_${stdenv.buildPlatform.config}"="${cxxForBuild}" \
          "CC_${host-triple}"="${ccForHost}" \
          "CXX_${host-triple}"="${cxxForHost}" \
          "''${depKeys[@]}" \
          cargo build ${buildMode} ${commonCargoArgs} \
            --message-format=json-render-diagnostics >cargo-output.json
      )
    '';

    setBuildEnv = ''
      isProcMacro="$( \
        remarshal -if toml -of json Cargo.original.toml \
        | jq -r 'if .lib."proc-macro" or .lib."proc_macro" then "1" else "" end' \
      )"
      crateName="$(
        remarshal -if toml -of json Cargo.original.toml \
        | jq -r 'if .lib."name" then .lib."name" else "${replaceChars [ "-" ] [ "_" ] name}" end' \
      )"
      . ${./utils.sh}
      export CARGO_VERBOSE=`cargoVerbosityLevel $NIX_DEBUG`
      export NIX_RUST_METADATA=`extractHash $out`
      export CARGO_HOME=`pwd`/.cargo
      linkFlags=(`makeExternCrateFlags $dependencies $devDependencies`)
      buildLinkFlags=(`makeExternCrateFlags $buildDependencies`)

      export NIX_RUST_LINK_FLAGS="''${linkFlags[@]} $extraRustcFlags"
      export NIX_RUST_BUILD_LINK_FLAGS="''${buildLinkFlags[@]} $extraRustcBuildFlags"
      export crateName selfLib RUSTC_CUSTOM_ARGS_CRATES RUSTC_CUSTOM_ARGS

      export doInstallCheck=${builtins.toString doInstallCheck}

      depKeys=(`loadDepKeys $dependencies`)

      if (( NIX_DEBUG >= 1 )); then
        echo $NIX_RUST_LINK_FLAGS
        echo $NIX_RUST_BUILD_LINK_FLAGS
        for key in ''${depKeys[@]}; do
          echo $key
        done
      fi
    '';

    buildPhase = ''
      runHook preBuild
      runHook overrideCargoManifest
      runHook setBuildEnv
      runHook runCargo
      runHook postBuild
    '';

    preInstallPhases = optional doDoc "docPhase";

    docPhase =
      let
        docTargetPath =
          if stdenv.buildPlatform.config == host-triple
          then "doc-target"
          else "doc-target/${host-triple}";
      in
        ''
          runHook preDoc
          mkdir -p ${docTargetPath}/doc
          linkRustdocs ${docTargetPath} $dependencies $devDependencies
          (
            set -euo pipefail
            if (( NIX_DEBUG >= 1 )); then
              set -x
            fi
            env \
              "CC_${stdenv.buildPlatform.config}"="${ccForBuild}" \
              "CXX_${stdenv.buildPlatform.config}"="${cxxForBuild}" \
              "CC_${host-triple}"="${ccForHost}" \
              "CXX_${host-triple}"="${cxxForHost}" \
              "''${depKeys[@]}" \
              cargo doc ${commonCargoArgs} --target-dir doc-target
          )
          runHook postDoc
        '';

    dontInstall = compileMode != "build";
    dontFixup = compileMode != "build";

    installPhase = ''
      runHook preInstall
      mkdir -p $out/lib
      cargo_links="$(remarshal -if toml -of json Cargo.original.toml | jq -r '.package.links | select(. != null)')"
      install_crate "$cargo_links"
      runHook postInstall
    '';

    installCheckPhase = ''
      mkdir -p $out
      RUSTC_BOOTSTRAP=1 RUST_BACKTRACE=1 cargo ${compileMode} \
        ${optionalString (compileMode == "test" && release) "--release"} \
        -Zdoctest-xcompile \
        ${let flags = extraTestFlags name; in optionalString (builtins.length flags >= 0) (pkgs.lib.concatStringsSep " " ([ "--" ] ++ flags))}
    '';
  };
in
stdenv.mkDerivation drvAttrs
