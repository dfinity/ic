self: super:

let
  lib = self.lib;
  # `isMaster` somewhat assumes it's running on hydra, but we explicitly check
  # `isHydra` to clarify _and_ to future-proof the code.
  isHydraMaster = self.lib.isHydra && self.isMaster;
  shfmtOpts = "-i 4 -ci -bn";
  checkTestRunners = name: where: self.stdenvNoCC.mkDerivation
    {
      name = "${name}-check-runner";
      buildInputs = [ self.shfmt ];
      src = lib.noNixFiles (lib.gitOnlySource where);
      phases = [ "configurePhase" "unpackPhase" "buildPhase" ];
      buildPhase = ''
        echo "Checking runner for $name"
        if ! shfmt ${shfmtOpts} -d $src/run; then
          echo "Please run"
          echo "${self.shfmt}/bin/shfmt ${shfmtOpts} -w tests/integration/${builtins.replaceStrings [ "-tests" ] [ "" ] name}/run"
          exit 1
        fi
        echo OK > $out
      '';
    };
  mkIntegrationScenarios = name: deps: where:
    let
      runScenario = scName: src: scenario: self.stdenvNoCC.mkDerivation
        {
          __darwinAllowLocalNetworking = true;
          name = "${name}--${scName}";
          src = lib.noNixFiles (lib.gitOnlySource src);
          buildInputs = deps ++ [ self.nc ];

          phases = [ "configurePhase" "unpackPhase" "buildPhase" ];
          buildPhase = ''
            echo "Running ${scenario}"

            cp $src/run ./run
            patchShebangs ./run

            if [[ -x $src/with-starter ]]; then
                cp $src/with-starter ./with-starter
                patchShebangs ./with-starter
                scenario=$src/${scenario} ./with-starter ./run

                if [[ ${scenario} != scenarios/checkpoint_recover.json ]]; then
                    scenario=$src/${scenario} \
                      ic-runner \
                        --nodes 1 \
                        --timeout 120 \
                        --dont-check-sigs \
                        --command ./run
                fi
            else
                scenario=$src/${scenario} ./run
            fi

            echo OK > $out
          '';
        };
      scenariosPaths = builtins.readDir (where + "/scenarios");
      # Creates an attribute set from scenario name to derivation.
      # XXX: the scenario names must _not_ contain numbers or dots (.), otherwise
      # Nix silently doesn't build the derivation.
      scenarios = lib.mapAttrs' (
        k: _:
          rec {
            name = lib.removeSuffix ".json" k;
            value = runScenario name where "scenarios/${k}";
          }
      )
        scenariosPaths;
      checkRunner = checkTestRunners name where;
    in
      self.recurseIntoAttrs (
        scenarios // {
          inherit checkRunner;
        }
      );
in

{ ic-testlib = { inherit mkIntegrationScenarios; }; }
