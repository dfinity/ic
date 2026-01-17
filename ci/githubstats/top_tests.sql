SELECT
  label AS label,

  COUNT(*) AS total_count,

  SUM(
    CASE
      WHEN overall_status <> 1 THEN 1
      ELSE 0
    END
  ) AS non_success_count,

  ROUND(
    (SUM
      (CASE
        WHEN overall_status <> 1 THEN 1
        ELSE 0
      END
      ) * 100.0
    ) / COUNT(*),
    2
  ) AS non_success_rate,

  SUM(
    CASE
      WHEN overall_status = 2 THEN 1
      ELSE 0
    END
  ) AS flaky_count,

  ROUND(
    (SUM
      (CASE
        WHEN overall_status = 2 THEN 1
        ELSE 0
      END) * 100.0
    ) / COUNT(*),
    2
  ) AS flaky_rate,

  SUM(
    CASE
      WHEN overall_status = 3 THEN 1
      ELSE 0
    END
  ) AS timeout_count,

  ROUND(
    (SUM
      (CASE
        WHEN overall_status = 3
        THEN 1 ELSE 0
      END) * 100.0
    ) / COUNT(*),
    2
  ) AS timeout_rate,

  SUM(
    CASE
      WHEN overall_status = 4 THEN 1
      ELSE 0
    END
  ) AS fail_count,

  ROUND(
    (SUM
      (CASE
        WHEN overall_status = 4 THEN 1
        ELSE 0
      END) * 100.0
    ) / COUNT(*),
    2
  ) AS fail_rate,

  (percentile_disc(0.9) WITHIN GROUP (ORDER BY total_run_duration)
  * INTERVAL '1 second'
  ) AS p90_duration

FROM
  bazel_tests

WHERE
  '$period' = '' OR first_start_time > now() - ('1 $period'::interval)

GROUP BY label

ORDER BY $order_by DESC

LIMIT $N