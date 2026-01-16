SELECT
  bi.build_date
, bt.total_run_duration / 60 AS total_run_duration_min
, CASE
      WHEN bt.overall_status = 1 THEN 'SUCCESS'
      WHEN bt.overall_status = 2 THEN 'FLAKY'
      WHEN bt.overall_status = 3 THEN 'TIMEOUT'
      WHEN bt.overall_status = 4 THEN 'FAILED'
  END AS status
, 'https://dash.idx.dfinity.network/invocation/' || bi.build_id AS buildbuddy_url
, bi.head_branch
, 'https://github.com/dfinity/ic/commit/' || bi.head_sha AS commit
FROM bazel_tests       AS bt
JOIN bazel_invocations AS bi ON bt.build_id = bi.build_id
WHERE
   bt.label = '$test_target'
   AND bt.overall_status IN ($overall_statuses)
   AND
     CASE
       WHEN '$period' <> '' THEN bi.build_date > now() - ('1 $period'::interval)
       ELSE TRUE
     END
ORDER BY bi.build_date DESC;