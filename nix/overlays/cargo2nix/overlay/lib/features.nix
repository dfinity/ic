{ lib }:
let
  expandFeatures =
    let
      inherit (builtins) attrNames concatMap listToAttrs;
      inherit (lib) splitString;
    in
      features: listToAttrs
        (
          map (feature: { name = feature; value = {}; })
            (
              concatMap (feature: [ feature (builtins.head (splitString "/" feature)) ])
                features
            )
        );
in
{ inherit expandFeatures; }
