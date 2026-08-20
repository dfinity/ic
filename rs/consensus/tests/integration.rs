#[cfg(test)]
mod framework;

use crate::framework::{ComponentModifier, ConsensusRunnerConfig, TestRunner, malicious};
use ic_types::malicious_flags::MaliciousFlags;
use rand::Rng;
use rand_chacha::{ChaChaRng, rand_core::SeedableRng};

#[test]
fn multiple_nodes_are_live() -> Result<(), String> {
    // allow settings to be customized when running from commandline
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            TestRunner::new(config, true).run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn single_node_is_live() {
    let config = ConsensusRunnerConfig {
        num_nodes: 1,
        num_rounds: 126,
        ..Default::default()
    };
    TestRunner::new(config, true).run_n_rounds_and_collect_hashes();
}

#[test]
fn master_pubkeys_are_produced() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|mut config| {
            // make sure we run at least 60 rounds
            if config.num_rounds < 60 {
                config.num_rounds = 60;
            }
            assert!(TestRunner::new(config, true).run_n_rounds_and_check_pubkeys());
        })
}

#[ignore]
#[test]
fn multiple_nodes_are_deterministic() {
    let run = || {
        let config = ConsensusRunnerConfig {
            num_nodes: 4,
            num_rounds: 10,
            ..Default::default()
        };
        TestRunner::new(config, true).run_n_rounds_and_collect_hashes()
    };
    assert_eq!(run(), run());
}

#[test]
fn minority_invalid_notary_share_signature_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                malicious.push(malicious::invalid_notary_share_signature())
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn majority_invalid_notary_share_signature_would_stuck() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..(config.num_nodes / 3 + 1) {
                malicious.push(malicious::invalid_notary_share_signature())
            }
            TestRunner::new(config, false)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn minority_absent_notary_share_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                malicious.push(malicious::absent_notary_share());
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn majority_absent_notary_share_signature_would_stuck() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..(config.num_nodes / 3 + 1) {
                malicious.push(malicious::absent_notary_share());
            }
            TestRunner::new(config, false)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn minority_maliciouly_notarize_all_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_notarize_all: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn minority_maliciouly_finalize_all_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_finalize_all: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

/*
 * FIXME: This may fail when multiple blocks are finalized at a given round,
 * but not always. So it is still probabilistic.
 *
 * Also when it fails, it may exhibit unexpected behavior (e.g. panic) because
 * the invariant of having at most one finalized block each round is broken.
 * So we don't have a good way to reliably catch this.
 */
#[ignore]
#[test]
fn majority_maliciouly_finalize_all_would_diverge() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..((config.num_nodes - 1) / 3 * 2 + 1) {
                let malicious_flags = MaliciousFlags {
                    maliciously_notarize_all: true, // to create more than 1 branches
                    maliciously_finalize_all: true, // to finalize more than 1 branches
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            TestRunner::new(config, false)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn minority_maliciouly_idkg_dealers_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|mut config| {
            // make sure we run at least 60 rounds
            if config.num_rounds < 60 {
                config.num_rounds = 60;
            }
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_corrupt_idkg_dealings: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            assert!(
                TestRunner::new(config, true)
                    .with_modifiers(malicious)
                    .run_n_rounds_and_check_pubkeys()
            )
        })
}

#[test]
fn stalled_clocks_with_f_malicious_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|mut config| {
            config.stall_clocks = true;
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..f {
                malicious.push(malicious::absent_notary_share())
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

/// Run a test subnets with `num_nodes` many nodes, out of which there are `num_nodes_equivocating` many equivocating blockmaker
fn equivocating_block_maker_test(
    num_nodes: usize,
    num_nodes_equivocating: usize,
    finish: bool,
) -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(num_nodes, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            let malicious_flags = MaliciousFlags {
                maliciously_propose_equivocating_blocks: true,
                ..MaliciousFlags::default()
            };
            for _ in 0..num_nodes_equivocating {
                malicious.push(malicious::with_malicious_flags(malicious_flags.clone()));
            }
            TestRunner::new(config, finish)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

/// Tests that as long as there is a single block maker that does not equivocate, we will occasionally
/// have a block that gets finalized
#[test]
fn one_node_equivocating_passes() -> Result<(), String> {
    equivocating_block_maker_test(4, 1, true)
}

/// Tests that if all blockmakers are equivocating, we will not be able to finalize any block ever
#[test]
fn all_nodes_equivocating_fail() -> Result<(), String> {
    equivocating_block_maker_test(4, 4, false)
}
