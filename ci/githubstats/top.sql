SELECT
  label AS label,

  COUNT(*) AS total,

         SUM(CASE WHEN overall_status <> 1 THEN 1 ELSE 0 END)                         AS non_success,
  ROUND((SUM(CASE WHEN overall_status <> 1 THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2) AS non_success_rate,

         SUM(CASE WHEN overall_status = 2 THEN 1 ELSE 0 END)                          AS flaky,
  ROUND((SUM(CASE WHEN overall_status = 2 THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2)  AS flaky_rate,

         SUM(CASE WHEN overall_status = 3 THEN 1 ELSE 0 END)                          AS timeout,
  ROUND((SUM(CASE WHEN overall_status = 3 THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2)  AS timeout_rate,

         SUM(CASE WHEN overall_status = 4 THEN 1 ELSE 0 END)                          AS fail,
  ROUND((SUM(CASE WHEN overall_status = 4 THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2)  AS fail_rate,

  percentile_disc(0.9) WITHIN GROUP (ORDER BY total_run_duration) * INTERVAL '1 second' AS p90_duration

FROM
  workflow_runs     AS wr JOIN
  bazel_invocations AS bi ON wr.id = bi.run_id JOIN
  bazel_tests       AS bt ON bi.build_id = bt.build_id

WHERE
  ({hide} = '' OR bt.label NOT LIKE {hide})
  AND ('{period}' = '' OR bt.first_start_time > now() - ('1 {period}'::interval))
  AND (NOT {only_prs} OR wr.event_type = 'pull_request')
  AND ({branch} = '' OR wr.head_branch LIKE {branch})

GROUP BY label

ORDER BY {order_by} DESC

LIMIT {N}