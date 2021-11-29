let
  profileNames = [
    "release"
    "dev"
    "test"
    "bench"
    "__noProfile" # A placeholder profile for build scripts, which don't respect any profiles.
  ];
in
{}:
  {
    # Decides which profile to use based on compile mode and whether release is enabled.
    # Ported from https://github.com/rust-lang/cargo/blob/rust-1.38.0/src/cargo/core/profiles.rs#L86.
    decideProfile = compileMode: release:
      if compileMode == "test" || compileMode == "bench"
      then if release then "bench" else "test"
      else if compileMode == "build" || compileMode == null
      then if release then "release" else "dev"
      else
        throw "unknown compile mode";

    # Generates a set whose keys are all available profile names (see above).
    # Type: Map ProfileName Profile -> (ProfileName -> Profile -> a) -> Map ProfileName a
    genDrvsByProfile = profilesByName: f:
      let
        nullProfileDrv = f { profileName = "__noProfile"; profile = null; };
      in
        builtins.listToAttrs
          (
            builtins.map
              (
                profileName: {
                  name = profileName;
                  value =
                    if profilesByName ? "${profileName}"
                    then f { inherit profileName; profile = profilesByName.${profileName}; }
                    else nullProfileDrv;
                }
              )
              profileNames
          );
  }
