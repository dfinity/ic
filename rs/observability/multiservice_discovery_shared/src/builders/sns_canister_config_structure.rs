use std::collections::HashMap;

use serde::Serialize;

use crate::contracts::sns::Sns;

use super::{
    log_vector_config_structure::VectorRemapTransform,
    vector_config_enriched::{VectorConfigEnriched, VectorSource, VectorTransform},
};

#[derive(Debug, Clone)]
pub struct SnsCanisterConfigStructure {
    pub script_path: String,
    pub data_folder: String,
    pub restart_on_exit: bool,
    pub include_stderr: bool,
}

static SCRAPABLE_TYPES: [&str; 3] = ["root", "swap", "governance"];

impl SnsCanisterConfigStructure {
    pub fn build(&self, snses: Vec<Sns>) -> String {
        let mut config = VectorConfigEnriched::new();

        for sns in snses {
            for canister in sns.canisters {
                if !SCRAPABLE_TYPES.contains(&canister.canister_type.as_str()) {
                    continue;
                }

                let key = canister.canister_id.to_string();
                let source = VectorScriptSource {
                    _type: "exec".to_string(),
                    command: [
                        self.script_path.as_str(),
                        "--url",
                        format!("https://{}.raw.icp0.io/logs", canister.canister_id).as_str(),
                    ]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                    mode: "streaming".to_string(),
                    streaming: SourceStreamingWrapper {
                        respawn_on_exit: self.restart_on_exit,
                    },
                    include_stderr: self.include_stderr,
                };

                let transform = VectorRemapTransform {
                    _type: "remap".to_string(),
                    inputs: vec![key.clone()],
                    source: vec![
                        ("canister_id", canister.canister_id),
                        ("canister_type", canister.canister_type),
                        ("module_hash", canister.module_hash),
                    ]
                    .into_iter()
                    .map(|(k, v)| format!(".{} = \"{}\"", k, v))
                    .collect::<Vec<String>>()
                    .join("\n"),
                };

                let mut sources = HashMap::new();
                sources.insert(key.clone(), Box::new(source) as Box<dyn VectorSource>);

                let mut transforms = HashMap::new();
                transforms.insert(
                    format!("{}-transform", key),
                    Box::new(transform) as Box<dyn VectorTransform>,
                );

                config.add_target_group(sources, transforms)
            }
        }

        serde_json::to_string_pretty(&config).unwrap()
    }
}

#[derive(Debug, Clone, Serialize)]
struct VectorScriptSource {
    #[serde(rename = "type")]
    _type: String,
    command: Vec<String>,
    mode: String,
    streaming: SourceStreamingWrapper,
    include_stderr: bool,
}

impl VectorSource for VectorScriptSource {
    fn clone_dyn(&self) -> Box<dyn VectorSource> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone, Serialize)]
struct SourceStreamingWrapper {
    respawn_on_exit: bool,
}

#[derive(Debug, Clone, Serialize)]
struct VectorJournaldSource {
    #[serde(rename = "type")]
    _type: String,
    data_dir: String,
    journal_directory: String,
}

impl VectorSource for VectorJournaldSource {
    fn clone_dyn(&self) -> Box<dyn VectorSource> {
        Box::new(self.clone())
    }
}
