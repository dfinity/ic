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

      $SHELL_WRAPPER pipenv --python 3
      $SHELL_WRAPPER pipenv install -r requirements.txt

      $SHELL_WRAPPER pipenv run experiments/{{benchmark_path}} --testnet $TESTNET --wg_subnet 2 --wg_testnet $TESTNET

      # Critical experiment runs passed, disable strict failure mode
      set +eo pipefail
      
      TIMESTAMP=$(find results/"$GIT_REVISION" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" | sort -nr | head -1)
      $SHELL_WRAPPER pipenv run python3 common/generate_report.py --base_dir="results/" --git_revision="$GIT_REVISION" --timestamp="$TIMESTAMP"
      {{#if is_max_capacity_run}}
      $SHELL_WRAPPER pipenv run python3 common/notify_dashboard.py --base_dir="results/" --git_revision="$GIT_REVISION" --timestamp="$TIMESTAMP" --is_max_capacity_run="True" --branch="$CURRENT_BRANCH" --is_max_capacity_run="True" --gitlab_job_id="$CI_JOB_ID"
      {{/if}}

      find . -name  'workload-generator*stderr.txt' -print0 | xargs -0 pigz
      cd -

      $SHELL_WRAPPER rclone --config="${CI_PROJECT_DIR}/.rclone.conf"  copyto "scalability/results/$GIT_REVISION" "performance-testing:performance-testing-results/$GIT_REVISION"
