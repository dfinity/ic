WITH "top" AS (
  SELECT
    label,

    COUNT(*) AS "total",

           SUM(CASE WHEN overall_status <> 1 THEN 1 ELSE 0 END)                         AS "non_success",
    ROUND((SUM(CASE WHEN overall_status <> 1 THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2) AS "non_success%",

           SUM(CASE WHEN overall_status = 2 THEN 1 ELSE 0 END)                          AS "flaky",
    ROUND((SUM(CASE WHEN overall_status = 2 THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2)  AS "flaky%",

           SUM(CASE WHEN overall_status = 3 THEN 1 ELSE 0 END)                          AS "timeout",
    ROUND((SUM(CASE WHEN overall_status = 3 THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2)  AS "timeout%",

           SUM(CASE WHEN overall_status = 4 THEN 1 ELSE 0 END)                          AS "fail",
    ROUND((SUM(CASE WHEN overall_status = 4 THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2)  AS "fail%",

    percentile_disc(0.9) WITHIN GROUP (ORDER BY total_run_duration) * INTERVAL '1 second' AS "duration_p90"

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
)
SELECT * FROM "top" WHERE {condition}
