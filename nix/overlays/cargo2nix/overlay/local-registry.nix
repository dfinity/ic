{ runCommandCC, linkFarm, lib }:
{ name, crates ? [] }:
let
  cratesByName =
    lib.foldl'
      (
        crates: crate:
          lib.recursiveUpdate
            crates
            {
              ${crate.name}.${crate.version} = crate;
            }
      )
      {}
      crates;

  aggregateCrateVersions = crate:
    lib.concatStringsSep
      "\n"
      (
        map
          (crate: builtins.toJSON crate.registry-entry)
          (lib.attrValues crate)
      );

  crateToRegistryPath = name: crate:
    let
      inherit (builtins) length elemAt toFile;
      chars = lib.stringToCharacters name;
      path = toFile "${name}-registry-entry" (aggregateCrateVersions crate);
      charAt = elemAt chars;
    in
      assert length chars > 0;
      if length chars == 1 then
        {
          name = "1/${name}";
          inherit path;
        }
      else if length chars == 2 then
        {
          name = "2/${name}";
          inherit path;
        }
      else if length chars == 3 then
        {
          name = "3/${charAt 0}/${name}";
          inherit path;
        }
      else
        {
          name = "${charAt 0}${charAt 1}/${charAt 2}${charAt 3}/${name}";
          inherit path;
        };

  registry-hierarchy = lib.flatten (lib.mapAttrsToList crateToRegistryPath cratesByName);

  registry-index = linkFarm "${name}-registry-index" registry-hierarchy;

  paths =
    [
      {
        name = "index";
        path = registry-index;
      }
    ] ++ map
      (
        { src, name, version, crate, ... }:
          {
            name = "${name}-${version}.crate";
            path = crate;
          }
      )
      crates;
in
linkFarm "${name}-offline" paths
