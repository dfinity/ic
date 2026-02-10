WITH
  "core" AS (
    SELECT
      label,
      COUNT(*) AS "total",
      SUM(CASE WHEN overall_status <> 1 THEN 1 ELSE 0 END) AS "non_success",
      SUM(CASE WHEN overall_status = 2 THEN 1 ELSE 0 END)  AS "flaky",
      SUM(CASE WHEN overall_status = 3 THEN 1 ELSE 0 END)  AS "timeout",
      SUM(CASE WHEN overall_status = 4 THEN 1 ELSE 0 END)  AS "fail",
      percentile_disc(0.9) WITHIN GROUP (ORDER BY total_run_duration) * INTERVAL '1 second' AS "duration_p90"

    FROM
      workflow_runs     AS wr JOIN
      bazel_invocations AS bi ON wr.id = bi.run_id JOIN
      bazel_tests       AS bt ON bi.build_id = bt.build_id

    WHERE
      ({exclude} = '' OR bt.label NOT LIKE {exclude})
      AND ({include} = '' OR bt.label LIKE {include})
      AND ({time_filter})
      AND (NOT {only_prs} OR wr.event_type = 'pull_request')
      AND ({branch} = '' OR wr.head_branch LIKE {branch})

    GROUP BY label
  ),
  "top" AS (
    SELECT
      label,
      "total",
      "non_success",
      "flaky",
      "timeout",
      "fail",
      ROUND(("non_success" * 100.0) / "total", 1) AS "non_success%",
      ROUND(("flaky" * 100.0) / "total", 1)  AS "flaky%",
      ROUND(("timeout" * 100.0) / "total", 1)  AS "timeout%",
      ROUND(("fail" * 100.0) / "total", 1)  AS "fail%",
      "non_success" * "duration_p90" AS "impact",
      "duration_p90"

    FROM
      "core"

    ORDER BY {order_by} DESC

    LIMIT {N}
  )
SELECT * FROM "top" WHERE {condition}
