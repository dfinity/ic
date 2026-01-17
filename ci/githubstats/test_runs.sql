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
  bi.head_sha

FROM
  bazel_tests            AS bt
  JOIN bazel_invocations AS bi ON bt.build_id = bi.build_id
  JOIN workflow_runs     AS wr ON bi.run_id = wr.id

WHERE
   bt.label = '$test_target'
   AND bt.overall_status IN ($overall_statuses)
   AND ('$period' = '' OR bi.build_date > now() - ('1 $period'::interval))
   AND (NOT $only_prs OR wr.event_type = 'pull_request')

ORDER BY bi.build_date DESC