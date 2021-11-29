# See the ./repo-deps script in this directory for a motivation for and
# documentation of this file.
{ file }:
let
  repoRoot = toString ../.;

  hasPrefix = pref: str:
    builtins.substring 0 (builtins.stringLength pref) str == pref;

  hasSuffix = suffix: content:
    let
      lenContent = builtins.stringLength content;
      lenSuffix = builtins.stringLength suffix;
    in
      lenContent >= lenSuffix && builtins.substring (lenContent - lenSuffix) lenContent content == suffix;

  traceIfRepoFile = path: x:
    let
      pathStr = toString path;
    in
      if hasPrefix repoRoot pathStr
      then builtins.trace (builtins.substring (builtins.stringLength repoRoot + 1) (builtins.stringLength pathStr) pathStr) x
      else x;

  overrides = {
    import = path: overrides.scopedImport overrides path;
    scopedImport = attrs: path:
      let
        realPath =
          if hasSuffix ".nix" path
          then path
          else path + "/default.nix";
      in
        traceIfRepoFile realPath (builtins.scopedImport (overrides // attrs) path);
    builtins = builtins // {
      readFile = file: traceIfRepoFile file (builtins.readFile file);
      readDir = dir: traceIfRepoFile dir (builtins.readDir dir);
      path = args: traceIfRepoFile args.path (builtins.path args);
      fetchGit = args:
        if builtins.isPath args
        then traceIfRepoFile args (builtins.fetchGit args)
        else builtins.fetchGit args;
    };
  };

  imported =
    let
      raw = overrides.scopedImport overrides file;
    in
      if builtins.isFunction raw
      then raw {}
      else raw;
in
imported
