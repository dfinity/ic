// use ic_state_machine_tests::StateMachine;
// use ic_test_utilities_load_wasm::load_wasm;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::ResolvedStatePair;
use crate::TlaConstantAssignment;

pub trait HasTlaRepr {
    fn to_tla_state(&self) -> HashMap<String, String>;
}

#[derive(Debug)]
pub enum ApalacheError {
    CheckFailed(String),
    SetupError(String),
}

#[derive(Debug)]
pub struct TlaCheckError {
    pub apalache_error: ApalacheError,
    pub pair: ResolvedStatePair,
    pub constants: TlaConstantAssignment,
}

const INIT_PREDICATE_NAME: &str = "Check_Code_Link_Init";
const NEXT_PREDICATE_NAME: &str = "Check_Code_Link_Next";

fn mk_init_predicate(pre_state: HashMap<String, String>) -> String {
    let new_init_predicate = INIT_PREDICATE_NAME.to_string();
    let pre_state_constraint = pre_state
        .into_iter()
        .map(|(k, v)| format!("  /\\ {} = {}", k, v))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{} ==\n{}", new_init_predicate, pre_state_constraint)
}

fn add_parameters(operator: String, parameters: Vec<String>) -> String {
    let param_string = if parameters.is_empty() {
        String::new()
    } else {
        format!("({})", parameters.join(", "))
    };
    operator + &param_string
}

fn mk_transition_predicate(
    post_state: HashMap<String, String>,
    old_transition_predicate: String,
    predicate_parameters: Vec<String>,
) -> String {
    let new_next_predicate = NEXT_PREDICATE_NAME.to_string();
    let post_state_constraint = post_state
        .into_iter()
        .map(|(k, v)| format!("  /\\ {}' = {}", k, v))
        .collect::<Vec<_>>()
        .join("\n");
    let old_transition_predicate =
        add_parameters(old_transition_predicate, predicate_parameters.clone());
    let new_next_predicate = add_parameters(new_next_predicate, predicate_parameters);
    format!(
        "{} ==\n  /\\ {}\n{}",
        new_next_predicate, old_transition_predicate, post_state_constraint,
    )
}

fn mk_constant_definitions(constants: HashMap<String, String>) -> Vec<String> {
    constants
        .iter()
        .map(|(k, v)| format!("{} == {}", k, v))
        .collect()
}

/* Check whether Apalache complains about deadlocks with traces of length one */
fn run_apalache(
    apalache_binary: &Path,
    tla_module: &Path,
    init_predicate: String,
    next_predicate: String,
) -> Result<(), ApalacheError> {
    let mut cmd = Command::new(apalache_binary);
    cmd.arg("check")
        .arg(format!("--init={}", init_predicate))
        .arg(format!("--next={}", next_predicate))
        .arg("--length=1")
        .arg(tla_module);
    cmd.status()
        .map_err(|e| ApalacheError::SetupError(e.to_string()))
        .and_then(|e| {
            if e.success() {
                Ok(())
            } else {
                Err(ApalacheError::CheckFailed(
                    format!(
                        "When checking file\n{:?}\nApalache returned the error: {}",
                        tla_module, e
                    )
                    .to_string(),
                ))
            }
        })
}

pub struct PredicateDescription {
    pub tla_module: PathBuf,
    pub transition_predicate: String,
    pub predicate_parameters: Vec<String>,
}

pub fn check_tla_code_link(
    apalache: &Path,
    predicate: PredicateDescription,
    state_pair: ResolvedStatePair,
    constants: TlaConstantAssignment,
) -> Result<(), TlaCheckError> {
    check_tla_code_link_raw(
        apalache,
        &predicate.tla_module,
        predicate.transition_predicate,
        predicate.predicate_parameters,
        state_pair
            .start
            .0
             .0
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect(),
        state_pair
            .end
            .0
             .0
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect(),
        constants
            .constants
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect(),
    )
    .map_err(|e| TlaCheckError {
        apalache_error: e,
        pair: state_pair,
        constants,
    })
}

fn sha256_hex(input: Vec<u8>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    format!("{:x}", result)
}

/** Uses Apalache to check whether a trace step is allowed by the TLA+ transition.
 *
 * Returns an error if Apalache returns one, or if there's something wrong with
 * the setup.
 */
pub fn check_tla_code_link_raw(
    apalache: &Path,
    tla_module: &Path,
    transition_predicate: String,
    predicate_parameters: Vec<String>,
    pre_state: HashMap<String, String>,
    post_state: HashMap<String, String>,
    constants: HashMap<String, String>,
) -> Result<(), ApalacheError> {
    // The strategy:
    // 1. Copy the given TLA+ to a temporary file in the same directory (so that module imports still work)
    // 2. In the temporary file, create new Init and Next relations (under a different name) as follows:
    //    a. initial state is equal to the given pre_state
    //    b. next is a conjunction of the given transition predicate, and the requirement that the post state
    //       equals the given post_state
    // 3. Run Apalache on the result with a maximum trace length of 1 and check whether the model deadlocks; if it
    //    does deadlock, it means that the transition is not compatible with our pre-and post states

    fn new_module_with_predicates_and_constants(
        tla_module: &Path,
        predicates: Vec<String>,
        constants: Vec<String>,
    ) -> Result<PathBuf, String> {
        let parent_dir = tla_module.parent().ok_or(format!(
            "Can't get the parent directory of the alleged TLA module {}",
            tla_module.display()
        ))?;
        let module_name = tla_module
            .file_stem()
            .ok_or(format!(
                "Can't compute the module name of {}",
                tla_module.display()
            ))
            .map(|n| n.to_string_lossy())?;

        let module_text = fs::read_to_string(tla_module)
            .map_err(|_e| format!("Couldn't read from module {}", tla_module.display()))?;
        let (module_body, _comments) = module_text.split_once("\n====").ok_or(format!(
            "No module end delimiter in the module {}",
            tla_module.display()
        ))?;

        // Change the module name such that it fits the new file name
        // TODO: use uuids or something to prevent clashes
        let new_module_prefix = "Code_Link";
        let new_module_suffix = &sha256_hex(
            predicates
                .iter()
                .chain(constants.iter())
                .flat_map(|s| s.as_bytes())
                .cloned()
                .collect(),
        )[..32];
        let module_body = module_body.replace(
            format!("MODULE {}", module_name.clone()).as_str(),
            format!(
                "MODULE {}_{}_{}",
                new_module_prefix, module_name, new_module_suffix
            )
            .as_str(),
        );

        let module_body = module_body.replace(
            "\\* CODE_LINK_INSERT_CONSTANTS",
            constants.join("\n").as_str(),
        );
        let new_module = format!("{}\n{}\n====", module_body, predicates.join("\n"));
        let temp_file_path = parent_dir.join(format!(
            "{}_{}_{}.tla",
            new_module_prefix, module_name, new_module_suffix
        ));
        fs::write(temp_file_path.clone(), new_module).map_err(|e| e.to_string())?;
        Ok(temp_file_path)
    }

    let init_predicate = mk_init_predicate(pre_state);
    let trans_predicate =
        mk_transition_predicate(post_state, transition_predicate, predicate_parameters);
    let constant_definitions = mk_constant_definitions(constants);
    let new_module = new_module_with_predicates_and_constants(
        tla_module,
        vec![init_predicate, trans_predicate],
        constant_definitions,
    )
    .map_err(ApalacheError::SetupError)?;
    run_apalache(
        apalache,
        new_module.as_path(),
        INIT_PREDICATE_NAME.to_string(),
        NEXT_PREDICATE_NAME.to_string(),
    )?;
    // TODO: remove the temporary file if everything went well
    // fs::remove_file(new_module);
    Ok(())
}

#[test]
fn retrieve_btc() {}

#[cfg(test)]
impl HasTlaRepr for TlaCounterState {
    fn to_tla_state(&self) -> HashMap<String, String> {
        HashMap::from([("cnt".to_string(), self.cnt.to_string())])
    }
}

#[cfg(test)]
struct TlaCounterState {
    cnt: u32,
}

#[test]
fn basic_test() {
    let pre_state = TlaCounterState { cnt: 4 };
    let post_state = TlaCounterState { cnt: 6 };
    let apalache = get_apalache_path();
    let tla_module = project_root()
        .join("rs")
        .join("tla_code_link_poc")
        .join("tla")
        .join("Counter.tla");
    let result = check_tla_code_link_raw(
        &apalache,
        &tla_module,
        "Next".to_string(),
        vec![],
        pre_state.to_tla_state(),
        post_state.to_tla_state(),
        HashMap::default(),
    );
    assert!(
        result.is_ok(),
        "Apalache returned an error: {:?}",
        result.unwrap_err()
    );
}
