fn main() {
    canister_test::local_test_e(|r| async move {
        use criterion::Criterion;
        use std::time::Duration;

        let mut criterion = Criterion::default()
            .sample_size(10)
            .warm_up_time(Duration::new(10, 0));
        {
            use canister_test::*;
            use dfn_json::json;

            let mut group = criterion.benchmark_group("json encoding");

            let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

            let canister = proj.cargo_bin("json", &[]).install_(&r, Vec::new()).await?;

            group.bench_function("query", |bench| {
                bench.iter(|| async {
                    let res: Vec<String> = canister
                        .query_(
                            "reverse_words",
                            json,
                            vec!["reporters", "cover", "whales", "exploding"],
                        )
                        .await
                        .unwrap();

                    assert_eq!(res, vec!["exploding", "whales", "cover", "reporters"]);
                });
            });

            group.bench_function("update", |bench| {
                bench.iter(|| async {
                    let res: Vec<String> = canister
                        .update_(
                            "reverse_words",
                            json,
                            vec!["reporters", "cover", "whales", "exploding"],
                        )
                        .await
                        .unwrap();

                    assert_eq!(res, vec!["exploding", "whales", "cover", "reporters"]);
                });
            });
        }
        criterion.final_summary();
        Ok(())
    })
}
