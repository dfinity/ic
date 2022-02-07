use ic_crypto_test_utils_threshold_sigs::non_interactive::{
    create_dealing, create_transcript, load_transcript, retain_only_active_keys, verify_dealing,
    NiDkgTestEnvironment,
};
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTag;

use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode};

use std::path::PathBuf;

use nidkg_benches_test_vectors::NiDkgBenchDataManager;

criterion_main!(benches);
criterion_group!(benches, crypto_nidkg_benchmarks,);

fn crypto_nidkg_benchmarks(criterion: &mut Criterion) {
    let test_cases = vec![
        TestCase {
            sample_size: 50,
            sampling_mode: SamplingMode::Flat,
            num_of_nodes: 2,
            num_of_dealers: 1,
            dkg_tag: NiDkgTag::LowThreshold,
        },
        TestCase {
            sample_size: 30,
            sampling_mode: SamplingMode::Flat,
            num_of_nodes: 4,
            num_of_dealers: 3,
            dkg_tag: NiDkgTag::HighThreshold,
        },
        TestCase {
            sample_size: 10,
            sampling_mode: SamplingMode::Flat,
            num_of_nodes: 10,
            num_of_dealers: 4,
            dkg_tag: NiDkgTag::LowThreshold,
        },
        TestCase {
            sample_size: 10,
            sampling_mode: SamplingMode::Flat,
            num_of_nodes: 10,
            num_of_dealers: 7,
            dkg_tag: NiDkgTag::HighThreshold,
        },
        TestCase {
            sample_size: 10,
            sampling_mode: SamplingMode::Flat,
            num_of_nodes: 28,
            num_of_dealers: 19,
            dkg_tag: NiDkgTag::HighThreshold,
        },
    ];

    let toplevel_path: PathBuf = [
        &std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "benches/test_vectors_nidkg",
    ]
    .iter()
    .collect();
    let data_mgr = NiDkgBenchDataManager::new(toplevel_path);

    data_mgr.recreate_if_requested(&test_cases);

    for test_case in test_cases {
        let group = &mut criterion.benchmark_group(test_case.name());
        group
            .sample_size(test_case.sample_size)
            .sampling_mode(test_case.sampling_mode);

        bench_create_initial_dealing(group, &test_case, &data_mgr);
        bench_create_reshare_dealing(group, &test_case, &data_mgr);
        bench_verify_dealing(group, &test_case, &data_mgr);
        bench_create_transcript(group, &test_case, &data_mgr);
        bench_load_transcript(group, &test_case, &data_mgr);
        bench_retain_keys(group, &test_case, &data_mgr);
    }
}

fn bench_create_initial_dealing<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    data_mgr: &NiDkgBenchDataManager,
) {
    group.bench_function("create_initial_dealing", |bench| {
        let (env_path, config, creator_node_id) =
            data_mgr.get_create_initial_dealing_test_vectors(test_case);

        bench.iter_batched_ref(
            || NiDkgTestEnvironment::new_from_dir(&env_path),
            |env| create_dealing(&config, &env.crypto_components, creator_node_id),
            SmallInput,
        )
    });
}

fn bench_create_reshare_dealing<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    data_mgr: &NiDkgBenchDataManager,
) {
    group.bench_function("create_reshare_dealing", |bench| {
        let (env_path, config, creator_node_id) =
            data_mgr.get_create_reshare_dealing_test_vectors(test_case);

        bench.iter_batched_ref(
            || NiDkgTestEnvironment::new_from_dir(&env_path),
            |env| create_dealing(&config, &env.crypto_components, creator_node_id),
            SmallInput,
        )
    });
}

fn bench_verify_dealing<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    data_mgr: &NiDkgBenchDataManager,
) {
    group.bench_function("verify_dealing", |bench| {
        let (env_path, config, dealing, creator_node_id, verifier_node_id) =
            data_mgr.get_verify_dealing_test_vectors(test_case);

        bench.iter_batched_ref(
            || NiDkgTestEnvironment::new_from_dir(&env_path),
            |env| {
                verify_dealing(
                    &config,
                    &env.crypto_components,
                    creator_node_id,
                    verifier_node_id,
                    &dealing,
                )
            },
            SmallInput,
        )
    });
}

fn bench_create_transcript<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    data_mgr: &NiDkgBenchDataManager,
) {
    group.bench_function("create_transcript", |bench| {
        let (env_path, config, dealings, creator_node_id) =
            data_mgr.get_create_transcript_test_vectors(test_case);

        bench.iter_batched_ref(
            || NiDkgTestEnvironment::new_from_dir(&env_path),
            |env| create_transcript(&config, &env.crypto_components, &dealings, creator_node_id),
            SmallInput,
        )
    });
}

fn bench_load_transcript<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    data_mgr: &NiDkgBenchDataManager,
) {
    group.bench_function("load_transcript", |bench| {
        let (env_path, transcript, loader_node_id) =
            data_mgr.get_load_transcript_test_vectors(test_case);

        bench.iter_batched_ref(
            || NiDkgTestEnvironment::new_from_dir(&env_path),
            |env| load_transcript(&transcript, &env.crypto_components, loader_node_id),
            SmallInput,
        )
    });
}

fn bench_retain_keys<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    data_mgr: &NiDkgBenchDataManager,
) {
    group.bench_function("retain_active_keys", |bench| {
        let (env_path, retained_transcripts, retainer_node) =
            data_mgr.get_retain_keys_test_vectors(test_case);

        bench.iter_batched_ref(
            || NiDkgTestEnvironment::new_from_dir(&env_path),
            |env| {
                retain_only_active_keys(
                    &env.crypto_components,
                    retainer_node,
                    retained_transcripts.clone(),
                )
            },
            SmallInput,
        )
    });
}

pub struct TestCase {
    pub sample_size: usize,
    pub sampling_mode: SamplingMode,
    pub num_of_nodes: usize,
    pub num_of_dealers: usize,
    pub dkg_tag: NiDkgTag,
}

impl TestCase {
    pub fn name(&self) -> String {
        let tag_name = match self.dkg_tag {
            NiDkgTag::LowThreshold => "low",
            NiDkgTag::HighThreshold => "high",
        };
        format!(
            "crypto_nidkg_{}_nodes_{}_dealers_{}",
            self.num_of_nodes, self.num_of_dealers, tag_name
        )
    }
}

mod nidkg_benches_test_vectors {
    use super::TestCase;
    use ic_crypto_test_utils_threshold_sigs::non_interactive::{
        NiDkgTestEnvironment, RandomNiDkgConfig,
    };
    use serde::{de, ser};
    use std::collections::HashSet;
    use std::path::PathBuf;

    use ic_crypto_test_utils_threshold_sigs::non_interactive::{
        create_dealing, create_dealings, load_transcript, run_ni_dkg_and_create_single_transcript,
    };
    use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
    use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgTranscript};
    use ic_types::{NodeId, PrincipalId};
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::str::FromStr;

    pub struct NiDkgBenchDataManager {
        pub paths: TestVectorsPaths,
    }

    impl NiDkgBenchDataManager {
        pub fn new(toplevel_path: PathBuf) -> Self {
            Self {
                paths: TestVectorsPaths { toplevel_path },
            }
        }

        pub fn recreate_if_requested(&self, test_cases: &[TestCase]) {
            // To recreate all the test vectors for these benchmarks,
            // set the environment variable
            // `CRYPTO_BENCHES_NIDKG_RECREATE_TEST_VECTORS=yes`.
            let should_recreate = std::env::var("CRYPTO_BENCHES_NIDKG_RECREATE_TEST_VECTORS")
                .map_or("NO".to_string(), |s| s.to_ascii_uppercase())
                == "YES";
            if should_recreate {
                if std::path::Path::new(&self.paths.toplevel()).exists() {
                    std::fs::remove_dir_all(&self.paths.toplevel())
                        .expect("failed to remove old test vectors directory");
                }
                self.establish(test_cases);
            }
        }

        pub fn get_create_initial_dealing_test_vectors(
            &self,
            test_case: &TestCase,
        ) -> (PathBuf, NiDkgConfig, NodeId) {
            let testvec_dir = self.paths.create_initial_dealing(test_case);
            let config = read_data(&testvec_dir.join("config.cbor"));
            let creator_node_id = read_data(&testvec_dir.join("creator_node_id.cbor"));

            (
                self.paths.create_initial_dealing_env(test_case),
                config,
                creator_node_id,
            )
        }

        pub fn get_create_reshare_dealing_test_vectors(
            &self,
            test_case: &TestCase,
        ) -> (PathBuf, NiDkgConfig, NodeId) {
            let testvec_dir = self.paths.create_reshare_dealing(test_case);
            let config = read_data(&testvec_dir.join("config.cbor"));
            let creator_node_id = read_data(&testvec_dir.join("creator_node_id.cbor"));

            (
                self.paths.create_reshare_dealing_env(test_case),
                config,
                creator_node_id,
            )
        }

        pub fn get_verify_dealing_test_vectors(
            &self,
            test_case: &TestCase,
        ) -> (PathBuf, NiDkgConfig, NiDkgDealing, NodeId, NodeId) {
            let testvec_dir = self.paths.verify_dealing(test_case);
            let config = read_data(&testvec_dir.join("config.cbor"));
            let dealing = read_data(&testvec_dir.join("dealing.cbor"));
            let creator_node_id = read_data(&testvec_dir.join("creator_node_id.cbor"));
            let verifier_node_id = read_data(&testvec_dir.join("verifier_node_id.cbor"));

            (
                self.paths.verify_dealing_env(test_case),
                config,
                dealing,
                creator_node_id,
                verifier_node_id,
            )
        }

        pub fn get_create_transcript_test_vectors(
            &self,
            test_case: &TestCase,
        ) -> (PathBuf, NiDkgConfig, BTreeMap<NodeId, NiDkgDealing>, NodeId) {
            fn node_ids_from_dir_names(toplevel_path: &Path) -> BTreeMap<NodeId, PathBuf> {
                std::fs::read_dir(toplevel_path)
                    .expect("dealings directory doesn't exist")
                    .into_iter()
                    .map(|e| e.unwrap().path())
                    .filter(|e| e.is_file())
                    .map(|p| {
                        (
                            NodeId::from(
                                PrincipalId::from_str(
                                    p.with_extension("").file_name().unwrap().to_str().unwrap(),
                                )
                                .unwrap(),
                            ),
                            p,
                        )
                    })
                    .collect()
            }

            let testvec_dir = self.paths.create_transcript(test_case);
            let dealings_testvec_dir = self.paths.create_transcript_dealings(test_case);
            let config = read_data(&testvec_dir.join("config.cbor"));
            let dealings = node_ids_from_dir_names(&dealings_testvec_dir)
                .iter()
                .map(|(node_id, dealing_file)| {
                    let dealing = read_data(dealing_file);
                    (*node_id, dealing)
                })
                .collect();
            let creator_node_id = read_data(&testvec_dir.join("creator_node_id.cbor"));

            (
                self.paths.create_transcript_env(test_case),
                config,
                dealings,
                creator_node_id,
            )
        }

        pub fn get_load_transcript_test_vectors(
            &self,
            test_case: &TestCase,
        ) -> (PathBuf, NiDkgTranscript, NodeId) {
            let testvec_dir = self.paths.load_transcript(test_case);
            let transcript = read_data(&testvec_dir.join("transcript.cbor"));
            let loader_node_id = read_data(&testvec_dir.join("loader_node_id.cbor"));

            (
                self.paths.load_transcript_env(test_case),
                transcript,
                loader_node_id,
            )
        }

        pub fn get_retain_keys_test_vectors(
            &self,
            test_case: &TestCase,
        ) -> (PathBuf, HashSet<NiDkgTranscript>, NodeId) {
            let testvec_dir = self.paths.retain_keys(test_case);
            let transcript1 = read_data(&testvec_dir.join("transcript1.cbor"));
            let transcript2 = read_data(&testvec_dir.join("transcript2.cbor"));
            let mut retained_transcripts = HashSet::new();
            retained_transcripts.insert(transcript1);
            retained_transcripts.insert(transcript2);
            let retainer_node_id = read_data(&testvec_dir.join("retainer_node_id.cbor"));

            (
                self.paths.retain_keys_env(test_case),
                retained_transcripts,
                retainer_node_id,
            )
        }

        /// Create all test vectors, and write them to disk
        fn establish(&self, test_cases: &[TestCase]) {
            self.establish_create_initial_dealing_test_vectors(test_cases);
            self.establish_create_reshare_dealing_test_vectors(test_cases);
            self.establish_verify_dealing_test_vectors(test_cases);
            self.establish_create_transcript_test_vectors(test_cases);
            self.establish_load_transcript_test_vectors(test_cases);
            self.establish_retain_keys_test_vectors(test_cases);
        }

        fn establish_create_initial_dealing_test_vectors(&self, test_cases: &[TestCase]) {
            for test_case in test_cases {
                let (mut env, config, creator_node_id) =
                    prepare_create_initial_dealing_test_vectors(test_case);

                let testvec_dir = self.paths.create_initial_dealing(test_case);
                let env_testvec_dir = self.paths.create_initial_dealing_env(test_case);
                create_dir(&testvec_dir);
                create_dir(&env_testvec_dir);

                retain_only(&mut env, &creator_node_id);
                env.save_to_dir(&env_testvec_dir);

                write_data(&testvec_dir.join("config.cbor"), &config);
                write_data(&testvec_dir.join("creator_node_id.cbor"), &creator_node_id);
            }
        }

        fn establish_create_reshare_dealing_test_vectors(&self, test_cases: &[TestCase]) {
            for test_case in test_cases {
                let (mut env, config, creator_node_id) =
                    prepare_create_reshare_dealing_test_vectors(test_case);

                let testvec_dir = self.paths.create_reshare_dealing(test_case);
                create_dir(&testvec_dir);
                let env_testvec_dir = self.paths.create_reshare_dealing_env(test_case);
                create_dir(&env_testvec_dir);

                retain_only(&mut env, &creator_node_id);
                env.save_to_dir(&env_testvec_dir);

                write_data(&testvec_dir.join("config.cbor"), &config);
                write_data(&testvec_dir.join("creator_node_id.cbor"), &creator_node_id);
            }
        }

        fn establish_verify_dealing_test_vectors(&self, test_cases: &[TestCase]) {
            for test_case in test_cases {
                let (mut env, config, dealing, creator_node_id, verifier_node_id) =
                    prepare_verify_dealing_test_vectors(test_case);

                let testvec_dir = self.paths.verify_dealing(test_case);
                create_dir(&testvec_dir);
                let env_testvec_dir = self.paths.verify_dealing_env(test_case);
                create_dir(&env_testvec_dir);

                retain_only(&mut env, &verifier_node_id);
                env.save_to_dir(&env_testvec_dir);

                write_data(&testvec_dir.join("config.cbor"), &config);
                write_data(&testvec_dir.join("dealing.cbor"), &dealing);
                write_data(&testvec_dir.join("creator_node_id.cbor"), &creator_node_id);
                write_data(
                    &testvec_dir.join("verifier_node_id.cbor"),
                    &verifier_node_id,
                );
            }
        }

        fn establish_create_transcript_test_vectors(&self, test_cases: &[TestCase]) {
            for test_case in test_cases {
                let (mut env, config, dealings, creator_node_id) =
                    prepare_create_transcript_test_vectors(test_case);

                let testvec_dir = self.paths.create_transcript(test_case);
                let dealings_testvec_dir = self.paths.create_transcript_dealings(test_case);
                create_dir(&dealings_testvec_dir);
                let env_testvec_dir = self.paths.create_transcript_env(test_case);
                create_dir(&env_testvec_dir);

                retain_only(&mut env, &creator_node_id);
                env.save_to_dir(&env_testvec_dir);

                write_data(&testvec_dir.join("config.cbor"), &config);
                for (node_id, dealing) in dealings {
                    write_data(
                        &dealings_testvec_dir
                            .join(node_id.to_string())
                            .with_extension("cbor"),
                        &dealing,
                    );
                }
                write_data(&testvec_dir.join("creator_node_id.cbor"), &creator_node_id);
            }
        }

        fn establish_load_transcript_test_vectors(&self, test_cases: &[TestCase]) {
            for test_case in test_cases {
                let (mut env, transcript, loader_node_id) =
                    prepare_load_transcript_test_vectors(test_case);

                let testvec_dir = self.paths.load_transcript(test_case);
                create_dir(&testvec_dir);
                let env_testvec_dir = self.paths.load_transcript_env(test_case);
                create_dir(&env_testvec_dir);

                retain_only(&mut env, &loader_node_id);
                env.save_to_dir(&env_testvec_dir);

                write_data(&testvec_dir.join("transcript.cbor"), &transcript);
                write_data(&testvec_dir.join("loader_node_id.cbor"), &loader_node_id);
            }
        }

        fn establish_retain_keys_test_vectors(&self, test_cases: &[TestCase]) {
            for test_case in test_cases {
                let (mut env, transcript1, transcript2, retainer_node_id) =
                    prepare_retain_keys_test_vectors(test_case);

                let testvec_dir = self.paths.retain_keys(test_case);
                create_dir(&testvec_dir);
                let env_testvec_dir = self.paths.retain_keys_env(test_case);
                create_dir(&env_testvec_dir);

                retain_only(&mut env, &retainer_node_id);
                env.save_to_dir(&env_testvec_dir);

                write_data(
                    &testvec_dir.join("retainer_node_id.cbor"),
                    &retainer_node_id,
                );
                write_data(&testvec_dir.join("transcript1.cbor"), &transcript1);
                write_data(&testvec_dir.join("transcript2.cbor"), &transcript2);
            }
        }
    }

    fn prepare_create_initial_dealing_test_vectors(
        test_case: &TestCase,
    ) -> (NiDkgTestEnvironment, NiDkgConfig, NodeId) {
        let config = RandomNiDkgConfig::builder()
            .subnet_size(test_case.num_of_nodes)
            .dkg_tag(test_case.dkg_tag)
            .dealer_count(test_case.num_of_dealers)
            .build();
        let env = NiDkgTestEnvironment::new_for_config(config.get());
        let creator_node_id = config.random_dealer_id();

        (env, config.get().to_owned(), creator_node_id)
    }

    fn prepare_create_reshare_dealing_test_vectors(
        test_case: &TestCase,
    ) -> (NiDkgTestEnvironment, NiDkgConfig, NodeId) {
        let config0 = RandomNiDkgConfig::builder()
            .subnet_size(test_case.num_of_nodes)
            .dkg_tag(test_case.dkg_tag)
            .dealer_count(test_case.num_of_dealers)
            .build();
        let mut env = NiDkgTestEnvironment::new_for_config(config0.get());
        let transcript0 =
            run_ni_dkg_and_create_single_transcript(config0.get(), &env.crypto_components);
        let config = RandomNiDkgConfig::reshare(transcript0, 0..=0, test_case.num_of_nodes);
        env.update_for_config(config.get());
        let creator_node_id = config.random_dealer_id();
        load_transcript(
            config
                .get()
                .resharing_transcript()
                .as_ref()
                .expect("we know we have a resharing transcript"),
            &env.crypto_components,
            creator_node_id,
        );

        (env, config.get().to_owned(), creator_node_id)
    }

    fn prepare_verify_dealing_test_vectors(
        test_case: &TestCase,
    ) -> (
        NiDkgTestEnvironment,
        NiDkgConfig,
        NiDkgDealing,
        NodeId,
        NodeId,
    ) {
        let config = RandomNiDkgConfig::builder()
            .subnet_size(test_case.num_of_nodes)
            .dkg_tag(test_case.dkg_tag)
            .dealer_count(test_case.num_of_dealers)
            .build();
        let env = NiDkgTestEnvironment::new_for_config(config.get());
        let creator_node_id = config.random_dealer_id();
        let verifier_node_id = config.random_receiver_id();
        let dealing = create_dealing(config.get(), &env.crypto_components, creator_node_id);

        (
            env,
            config.get().to_owned(),
            dealing,
            creator_node_id,
            verifier_node_id,
        )
    }

    fn prepare_create_transcript_test_vectors(
        test_case: &TestCase,
    ) -> (
        NiDkgTestEnvironment,
        NiDkgConfig,
        BTreeMap<NodeId, NiDkgDealing>,
        NodeId,
    ) {
        let config = RandomNiDkgConfig::builder()
            .subnet_size(test_case.num_of_nodes)
            .dkg_tag(test_case.dkg_tag)
            .dealer_count(test_case.num_of_dealers)
            .build();
        let env = NiDkgTestEnvironment::new_for_config(config.get());
        let dealings = create_dealings(config.get(), &env.crypto_components);
        let creator_node_id = config.random_receiver_id();

        (env, config.get().to_owned(), dealings, creator_node_id)
    }

    fn prepare_load_transcript_test_vectors(
        test_case: &TestCase,
    ) -> (NiDkgTestEnvironment, NiDkgTranscript, NodeId) {
        let config = RandomNiDkgConfig::builder()
            .subnet_size(test_case.num_of_nodes)
            .dkg_tag(test_case.dkg_tag)
            .dealer_count(test_case.num_of_dealers)
            .build();
        let env = NiDkgTestEnvironment::new_for_config(config.get());
        let transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);
        let loader_node_id = config.random_receiver_id();

        (env, transcript, loader_node_id)
    }

    fn prepare_retain_keys_test_vectors(
        test_case: &TestCase,
    ) -> (
        NiDkgTestEnvironment,
        NiDkgTranscript,
        NiDkgTranscript,
        NodeId,
    ) {
        // Create just the initial remote sharing and transcript (using requested
        // tag/threshold).
        let config0 = RandomNiDkgConfig::builder()
            .subnet_size(test_case.num_of_nodes)
            .dkg_tag(test_case.dkg_tag)
            .dealer_count(test_case.num_of_dealers)
            .build();
        let mut env = NiDkgTestEnvironment::new_for_config(config0.get());
        let transcript0 =
            run_ni_dkg_and_create_single_transcript(config0.get(), &env.crypto_components);

        // Reshare locally amongst the same subnet.
        let config1 = RandomNiDkgConfig::reshare(transcript0, 0..=0, test_case.num_of_nodes);
        env.update_for_config(config1.get());
        let transcript1 =
            run_ni_dkg_and_create_single_transcript(config1.get(), &env.crypto_components);

        // Run an "inverted" DKG,
        // i.e. low if high is requested and high if low is requested
        // (the retain_only_active_keys_for_transcript checks that both
        // high- and low-threshold transcripts are retained)
        let config2 = config1.new_with_inverted_threshold();
        env.update_for_config(config2.get());
        let transcript2 =
            run_ni_dkg_and_create_single_transcript(config2.get(), &env.crypto_components);

        let retainer_node_id = config2.random_receiver_id();

        // We'll retain only the last two transcripts (one high, one low).
        (env, transcript1, transcript2, retainer_node_id)
    }

    fn retain_only(env: &mut NiDkgTestEnvironment, node_to_retain: &NodeId) {
        // NOTE: Can't use retain, because it's not stable until v1.53
        // env.crypto_components.retain(|&k, _| k == node_to_retain);

        let nodes_to_remove: Vec<NodeId> = env
            .crypto_components
            .keys()
            .copied()
            .filter(|n| n != node_to_retain)
            .collect();
        for node in nodes_to_remove {
            env.crypto_components.remove(&node);
        }
    }

    fn create_dir(path: &Path) {
        std::fs::create_dir_all(path).expect("failed to create test vector directory");
    }

    fn write_data<T>(path: &Path, data: &T)
    where
        T: ser::Serialize,
    {
        let file = std::fs::File::create(path).expect("failed to create data file");
        serde_cbor::to_writer(file, data).expect("failed to serialize data to file");
    }

    fn read_data<T>(path: &Path) -> T
    where
        T: de::DeserializeOwned,
    {
        let file = std::fs::File::open(path).expect("failed to open data file");
        serde_cbor::from_reader(&file).expect("failed to load data from file")
    }

    pub struct TestVectorsPaths {
        toplevel_path: PathBuf,
    }

    impl TestVectorsPaths {
        pub fn toplevel(&self) -> PathBuf {
            self.toplevel_path.clone()
        }

        pub fn create_initial_dealing(&self, test_case: &TestCase) -> PathBuf {
            self.toplevel_path
                .join("create_initial_dealing")
                .join(test_case.name())
        }

        pub fn create_initial_dealing_env(&self, test_case: &TestCase) -> PathBuf {
            self.create_initial_dealing(test_case).join("env")
        }

        pub fn create_reshare_dealing(&self, test_case: &TestCase) -> PathBuf {
            self.toplevel_path
                .join("create_reshare_dealing")
                .join(test_case.name())
        }

        pub fn create_reshare_dealing_env(&self, test_case: &TestCase) -> PathBuf {
            self.create_reshare_dealing(test_case).join("env")
        }

        pub fn verify_dealing(&self, test_case: &TestCase) -> PathBuf {
            self.toplevel_path
                .join("verify_dealing")
                .join(test_case.name())
        }

        pub fn verify_dealing_env(&self, test_case: &TestCase) -> PathBuf {
            self.verify_dealing(test_case).join("env")
        }

        pub fn create_transcript(&self, test_case: &TestCase) -> PathBuf {
            self.toplevel_path
                .join("create_transcript")
                .join(test_case.name())
        }

        pub fn create_transcript_env(&self, test_case: &TestCase) -> PathBuf {
            self.create_transcript(test_case).join("env")
        }

        pub fn create_transcript_dealings(&self, test_case: &TestCase) -> PathBuf {
            self.create_transcript(test_case).join("dealings")
        }

        pub fn load_transcript(&self, test_case: &TestCase) -> PathBuf {
            self.toplevel_path
                .join("load_transcript")
                .join(test_case.name())
        }

        pub fn load_transcript_env(&self, test_case: &TestCase) -> PathBuf {
            self.load_transcript(test_case).join("env")
        }

        pub fn retain_keys(&self, test_case: &TestCase) -> PathBuf {
            self.toplevel_path
                .join("retain_keys")
                .join(test_case.name())
        }

        pub fn retain_keys_env(&self, test_case: &TestCase) -> PathBuf {
            self.retain_keys(test_case).join("env")
        }
    }
}
