use std::collections::HashMap;

use ic_types::PrincipalId;
use serde::Serialize;

use crate::contracts::TargetDto;

use super::{
    log_vector_config_structure::{handle_ip, VectorRemapTransform},
    vector_config_enriched::{VectorConfigEnriched, VectorSource, VectorTransform},
    ConfigBuilder,
};

#[derive(Debug, Clone)]
pub struct ScriptLogConfigBuilderImpl {
    pub script_path: String,
    pub port: u64,
    pub journals_folder: String,
    pub worker_cursor_folder: String,
    pub data_folder: String,
    pub bn_port: u64,
    pub restart_on_exit: bool,
}

impl ConfigBuilder for ScriptLogConfigBuilderImpl {
    fn build(
        &self,
        target_groups: std::collections::BTreeSet<crate::contracts::TargetDto>,
    ) -> String {
        let mut config = VectorConfigEnriched::new();
        let mut edited_records: Vec<TargetDto> = vec![];

        // Work for boundary nodes
        for record in &target_groups {
            if let Some(record) = edited_records
                .iter_mut()
                .find(|r| r.targets.first().unwrap().ip() == record.targets.first().unwrap().ip())
            {
                record.custom_labels.clear();
                continue;
            }

            edited_records.push(record.clone());
        }

        for record in edited_records {
            for job in &record.jobs {
                let mut is_bn = false;
                let mut key = record.node_id.to_string();
                let anonymous = PrincipalId::new_anonymous().to_string();
                if key == anonymous {
                    key = record.clone().name;
                    is_bn = true;
                }
                let key = format!("{}-{}", key, job);
                let journald_source_key = format!("{}-journald", key);

                let script_source = VectorScriptSource {
                    _type: "exec".to_string(),
                    command: vec![
                        "python3.8",
                        self.script_path.as_str(),
                        "--url",
                        format!(
                            "http://[{}]:{}/entries",
                            handle_ip(record.clone(), job, is_bn),
                            match is_bn {
                                true => self.bn_port,
                                false => self.port,
                            }
                        )
                        .as_str(),
                        "--output-path",
                        format!("{}/{}/{}.journal", self.journals_folder, key, key).as_str(),
                        "--cursor-path",
                        format!("{}/{}/checkpoint.txt", self.worker_cursor_folder, key).as_str(),
                        "--expected-vector-cursor-path",
                        format!(
                            "{}/{}/checkpoint.txt",
                            self.data_folder, journald_source_key
                        )
                        .as_str(),
                    ]
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
                    mode: "streaming".to_string(),
                    streaming: SourceStreamingWrapper {
                        respawn_on_exit: self.restart_on_exit,
                    },
                };

                let journald_source = VectorJournaldSource {
                    _type: "journald".to_string(),
                    data_dir: self.data_folder.clone(),
                    journal_directory: format!("{}/{}", self.journals_folder, key),
                };

                let transform = VectorRemapTransform::from(
                    record.clone(),
                    *job,
                    journald_source_key.clone(),
                    is_bn,
                );

                let mut source_map = HashMap::new();
                source_map.insert(
                    format!("{}-script", key),
                    Box::new(script_source) as Box<dyn VectorSource>,
                );
                source_map.insert(
                    journald_source_key,
                    Box::new(journald_source) as Box<dyn VectorSource>,
                );

                let mut transform_map = HashMap::new();
                transform_map.insert(
                    format!("{}-transform", key),
                    Box::new(transform) as Box<dyn VectorTransform>,
                );

                config.add_target_group(source_map, transform_map);
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
