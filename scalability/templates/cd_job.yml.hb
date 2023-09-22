# BENCHMARK SUITE {{benchmark_name}}
{{benchmark_name}}:
  extends: .benchmark-test
  artifacts:
    when: always
    paths:
      - scalability/
  variables:
    TESTNET: "cdmax"
  script:
    - |
      set -eExou pipefail
      git fetch
      GIT_REVISION=$("$CI_PROJECT_DIR"/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh "$DISKIMG_BRANCH")

      $SHELL_WRAPPER timeout 1h ./testnet/tools/icos_deploy.sh $TESTNET --git-revision "$GIT_REVISION" --no-boundary-nodes
      cd ./scalability

      $SHELL_WRAPPER pip3 install -r requirements.txt

      $SHELL_WRAPPER python3 experiments/{{benchmark_path}} --testnet $TESTNET --wg_subnet 2 --wg_testnet $TESTNET

      # Critical experiment runs passed, disable strict failure mode
      set +eo pipefail

      TIMESTAMP=$(find results/"$GIT_REVISION" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" | sort -nr | head -1)
      $SHELL_WRAPPER python3 common/generate_report.py --base_dir="results/" --git_revision="$GIT_REVISION" --timestamp="$TIMESTAMP"

      find . -name  'workload-generator*stderr.txt' -print0 | xargs -0 pigz
      cd -

      $SHELL_WRAPPER rclone --config="${CI_PROJECT_DIR}/.rclone.conf"  copyto "scalability/results/$GIT_REVISION" "performance-testing:performance-testing-results/$GIT_REVISION"
