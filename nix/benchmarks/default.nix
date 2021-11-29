{ runCommandNoCC
, jq
, gnuplot
, lib
, curl
, stdenv
, isMaster
, labels
}:
{ results
, name
, src
}:
# Don't gate PR merges on a successful benchmark run by excluding the following
# jobs from the "required" aggregate job.
lib.mapAttrs (_name: lib.allowFailureOnPrs) rec {
  # Note that the `report` derivation depends on `src.rev` which means
  # that it has to rebuild for every new revision. For this reason
  # running the benchmarks (`run`) has been split up from `report`
  # such that it doesn't have to be rebuilt each time.
  inherit results;
  report =
    runCommandNoCC "benchmarks-report-${name}"
      {
        inherit (src) rev revCount;
        benchmark_results = results;
        nativeBuildInputs = [ jq ];
        preferLocalBuild = true;
        allowSubstitutes = false;
      }
      (builtins.readFile ./mk-report.sh);
  upload =
    lib.mkCheckedScript "activate" ./upload.sh
      {
        buildInputs = [ curl ];
        REPORTS = report;
      };
}
