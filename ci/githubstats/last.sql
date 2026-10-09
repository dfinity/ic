SELECT
  bt.first_start_time,

  bt.label,

  bt.total_run_duration * INTERVAL '1 second' AS "duration",

  CASE
      WHEN bt.overall_status = 1 THEN 'SUCCESS'
      WHEN bt.overall_status = 2 THEN 'FLAKY'
      WHEN bt.overall_status = 3 THEN 'TIMEOUT'
      WHEN bt.overall_status = 4 THEN 'FAILED'
  END AS "status",

  bi.build_id,

  bi.head_branch,

  CASE
      -- This is to fix the weird reality that all master commits have pull_request_number 855
      -- and pull_request_url https://api.github.com/repos/bit-cook/ic/pulls/855.
      WHEN wr.event_type = 'pull_request' THEN CAST(wr.pull_request_number AS TEXT)
      ELSE ''
  END AS "pull_request_number",

  bi.head_sha,

  bi.run_id,

  bi.job_name,

  -- Whether bazel took the result from the cache, i.e. its test summary says '(cached) PASSED':
  -- the test passed and all its runs were cached. (No test is sharded, and bazel_tests has no shard count.)
  -- The logs of such a result are those of the earlier bazel invocation that ran the test.
  COALESCE(bt.overall_status = 1 AND COALESCE(bt.total_num_cached, 0) >= GREATEST(bt.run_count, 1), FALSE) AS "cached"

FROM
  bazel_tests       AS bt JOIN
  bazel_invocations AS bi ON bt.build_id = bi.build_id LEFT JOIN LATERAL (
    -- Some invocations have no workflow run, and runs until 2025-10-09 can have a row per attempt, some without the PR number.
    SELECT * FROM workflow_runs WHERE id = bi.run_id ORDER BY pull_request_number IS NULL, run_attempt DESC LIMIT 1
  ) AS wr ON TRUE

WHERE
   ({test_target} = '' OR bt.label LIKE {test_target})
   AND bt.overall_status IN ({overall_statuses})
   AND ({time_filter})
   AND (NOT {only_prs} OR wr.event_type = 'pull_request')
   AND ({branch} = '' OR bi.head_branch LIKE {branch})
   AND ({job} = '' OR bi.job_name LIKE {job})
   AND (bi.job_name IS NULL OR bi.job_name NOT LIKE ALL({exclude_jobs}))
   AND (wr.event_type IS DISTINCT FROM 'pull_request' OR wr.pull_request_number != ALL({exclude_prs}))
   AND (bi.head_sha != ALL({exclude_commits}))

ORDER BY bt.first_start_time DESC