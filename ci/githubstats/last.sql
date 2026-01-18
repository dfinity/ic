SELECT
  bi.build_date,
  bt.total_run_duration * INTERVAL '1 second' AS total_run_duration,
  CASE
      WHEN bt.overall_status = 1 THEN 'SUCCESS'
      WHEN bt.overall_status = 2 THEN 'FLAKY'
      WHEN bt.overall_status = 3 THEN 'TIMEOUT'
      WHEN bt.overall_status = 4 THEN 'FAILED'
  END AS status,
  'https://dash.idx.dfinity.network/invocation/' || bi.build_id AS buildbuddy_url,
  bi.head_branch,
  CASE
      -- This is to fix the weird reality that all master commits have pull_request_number 855
      -- and pull_request_url https://api.github.com/repos/bit-cook/ic/pulls/855.
      WHEN wr.event_type = 'pull_request' THEN CAST(wr.pull_request_number AS TEXT)
      ELSE ''
  END AS pr,
  bi.head_sha

FROM
  workflow_runs     AS wr JOIN
  bazel_invocations AS bi ON wr.id = bi.run_id JOIN
  bazel_tests       AS bt ON bi.build_id = bt.build_id

WHERE
   bt.label = '$test_target'
   AND bt.overall_status IN ($overall_statuses)
   AND ('$period' = '' OR bi.build_date > now() - ('1 $period'::interval))
   AND (NOT $only_prs OR wr.event_type = 'pull_request')

ORDER BY bi.build_date DESC