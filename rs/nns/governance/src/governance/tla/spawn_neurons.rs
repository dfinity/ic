use lazy_static::lazy_static;
use std::collections::BTreeSet;
use tla_instrumentation::{
    Label, ResolvedStatePair, TlaConstantAssignment, ToTla, Update, VarAssignment,
};

use super::common::governance_account_id;
use super::{extract_common_constants, post_process_trace};

lazy_static! {
    pub static ref SPAWN_NEURONS_DESC: Update = {
        const PID: &str = "Spawn_Neurons";
        let default_locals = VarAssignment::new()
            .add("neuron_id", 0_u64.to_tla_value())
            .add("ready_to_spawn_ids", BTreeSet::<u64>::new().to_tla_value());
        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: Label::new("SpawnNeurons_Start"),
            end_label: Label::new("SpawnNeurons_Start"),
            process_id: PID.to_string(),
            canister_name: "governance".to_string(),
            post_process: |trace| {
                let constants = extract_spawn_neurons_constants(PID, trace);
                post_process_trace(trace);
                constants
            },
        }
    };
}

fn extract_spawn_neurons_constants(
    pid: &str,
    trace: &[ResolvedStatePair],
) -> TlaConstantAssignment {
    let maturity_modulation = (
        "MATURITY_BASIS_POINTS".to_string(),
        trace
            .first()
            .map(|pair| {
                pair.start
                    .get("cached_maturity_basis_points")
                    .expect("cached_maturity_basis_points not recorded")
                    .clone()
            })
            .unwrap_or(0_i32.to_tla_value()),
    );
    TlaConstantAssignment {
        constants: extract_common_constants(pid, trace)
            .into_iter()
            .chain([
                ("Minting_Account_Id".to_string(), governance_account_id()),
                maturity_modulation,
            ])
            .collect(),
    }
}
