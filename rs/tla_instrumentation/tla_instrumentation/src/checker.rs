// use ic_state_machine_tests::StateMachine;
// use ic_test_utilities_load_wasm::load_wasm;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

use crate::ResolvedStatePair;
use crate::TlaConstantAssignment;

pub trait HasTlaRepr {
    fn to_tla_state(&self) -> HashMap<String, String>;
}

pub enum ApalacheError {
    CheckFailed(Option<i32>, String),
    SetupError(String),
}

impl ApalacheError {
    pub fn is_likely_mismatch(&self) -> bool {
        match self {
            ApalacheError::CheckFailed(Some(code), _) => *code == 12,
            _ => false,
        }
    }
}

impl std::fmt::Debug for ApalacheError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApalacheError::SetupError(e) => f.write_str(&format!("Apalache setup error: {e}")),
            ApalacheError::CheckFailed(Some(code), s) => {
                f.write_str(&format!("{s}\n"))?;
                match *code {
                    12 =>
                    // code used to signal deadlocks
                    {
                        f.write_str("This is most likely a mismatch between the code and the model")
                    }
                    _ => f.write_str("This is most likely a problem with the model itself, or the TLA annotations (e.g., failing to log the values of some variables)"),
                }
            }
            ApalacheError::CheckFailed(None, s) => {
                f.write_str(s)?;
                f.write_str(
                    "The error code was not available - this is not expected, please report.",
                )
            }
        }
    }
}

pub struct TlaCheckError {
    pub model: PathBuf,
    pub apalache_error: ApalacheError,
    pub pair: ResolvedStatePair,
    pub constants: TlaConstantAssignment,
}

impl std::fmt::Debug for TlaCheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            &format!(
                "Apalache returned the error: {:?}\nThe error occured while checking the transition between:\n",
                self.apalache_error,
            )
        )?;
        f.debug_map().entries(self.pair.start.0.0.iter()).finish()?;
        f.write_str("\nand\n")?;
        f.debug_map().entries(self.pair.end.0.0.iter()).finish()?;
        f.write_str(&format!(
            "\nThe start and end locations in the code are:\n{}\nand\n{}",
            self.pair.start_source_location, self.pair.end_source_location
        ))?;
        f.write_str("\nThe constants are:\n")?;
        f.debug_map()
            .entries(self.constants.constants.iter())
            .finish()
    }
}

const INIT_PREDICATE_NAME: &str = "Check_Code_Link_Init";
const NEXT_PREDICATE_NAME: &str = "Check_Code_Link_Next";

fn mk_init_predicate(pre_state: HashMap<String, String>) -> String {
    let new_init_predicate = INIT_PREDICATE_NAME.to_string();
    let pre_state_constraint = pre_state
        .into_iter()
        .map(|(k, v)| format!("  /\\ {k} = {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{new_init_predicate} ==\n{pre_state_constraint}")
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
        .map(|(k, v)| format!("  /\\ {k}' = {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    let old_transition_predicate =
        add_parameters(old_transition_predicate, predicate_parameters.clone());
    let new_next_predicate = add_parameters(new_next_predicate, predicate_parameters);
    format!("{new_next_predicate} ==\n  /\\ {old_transition_predicate}\n{post_state_constraint}",)
}

fn mk_constant_definitions(constants: HashMap<String, String>) -> Vec<String> {
    constants
        .iter()
        .map(|(k, v)| format!("{k} == {v}"))
        .collect()
}

fn unique_tmp_dir() -> String {
    let test_tmpdir = std::env::var("TEST_TMPDIR").expect("TEST_TMPDIR not set");
    // Generate a unique subdirectory using a random UUID
    let subdir_name = Uuid::new_v4().to_string();
    let mut tmp_subdir = PathBuf::from(test_tmpdir);
    tmp_subdir.push(subdir_name);

    // Create the subdirectory
    fs::create_dir(&tmp_subdir).expect("Failed to create subdirectory in TEST_TMPDIR");

    // Convert the subdirectory path to a string
    tmp_subdir
        .to_str()
        .expect("Failed to convert subdirectory path to string")
        .to_string()
}

/* Check whether Apalache complains about deadlocks with traces of length one */
fn run_apalache(
    apalache_binary: &Path,
    tla_module: &Path,
    init_predicate: String,
    next_predicate: String,
) -> Result<(), ApalacheError> {
    let mut cmd = Command::new(apalache_binary);
    // TODO: There's a race condition when running multiple instances of Apalache in parallel,
    // as they all seem to try to write to the same file in /tmp. So we create a new temporary
    // directory for each run of Apalache based on the Bazel-provided temporary directory
    // and then feed that to the JRE, using the Apalache-specific JVM_ARGS environment variable.
    let tmp_subdir_str = unique_tmp_dir();
    // Construct the JVM_ARGS value so that Apalache uses the new temporary subdirectory
    let jvm_args = format!("-Djava.io.tmpdir={tmp_subdir_str}");

    cmd.arg("check")
        .arg(format!("--init={init_predicate}"))
        .arg(format!("--next={next_predicate}"))
        .arg("--length=1")
        .arg(tla_module)
        .env("JVM_ARGS", jvm_args);
    cmd.status()
        .map_err(|e| ApalacheError::SetupError(e.to_string()))
        .and_then(|e| {
            if e.success() {
                Ok(())
            } else {
                Err(ApalacheError::CheckFailed(
                    e.code(),
                    format!("When checking file\n{tla_module:?}\nApalache returned the error: {e}")
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

#[allow(clippy::result_large_err)]
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
        model: predicate.tla_module,
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
    format!("{result:x}")
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
            format!("MODULE {new_module_prefix}_{module_name}_{new_module_suffix}").as_str(),
        );

        let module_body = module_body.replace(
            "\\* CODE_LINK_INSERT_CONSTANTS",
            constants.join("\n").as_str(),
        );
        let new_module = format!("{}\n{}\n====", module_body, predicates.join("\n"));
        let temp_file_path = parent_dir.join(format!(
            "{new_module_prefix}_{module_name}_{new_module_suffix}.tla"
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
