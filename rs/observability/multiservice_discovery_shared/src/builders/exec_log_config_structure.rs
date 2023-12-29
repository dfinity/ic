use std::collections::HashMap;

use ic_types::PrincipalId;
use serde::Serialize;

use crate::contracts::target::TargetDto;

use super::{
    log_vector_config_structure::{handle_ip, VectorRemapTransform},
    vector_config_enriched::{VectorConfigEnriched, VectorSource, VectorTransform},
    ConfigBuilder,
};

#[derive(Debug, Clone)]
pub struct ExecLogConfigBuilderImpl {
    pub script_path: String,
    pub port: u64,
    pub bn_port: u64,
    pub cursor_folder: String,
    pub restart_on_exit: bool,
    pub include_stderr: bool,
}

impl ConfigBuilder for ExecLogConfigBuilderImpl {
    fn build(
        &self,
        target_groups: std::collections::BTreeSet<crate::contracts::target::TargetDto>,
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

                let source = VectorExecSource {
                    _type: "exec".to_string(),
                    command: vec![
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
                        "--name",
                        key.as_str(),
                        "--cursor-path",
                        format!("{}/{}/checkpoint.txt", self.cursor_folder, key).as_str(),
                    ]
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
                    mode: "streaming".to_string(),
                    streaming: SourceStreamingWrapper {
                        respawn_on_exit: self.restart_on_exit,
                    },
                    include_stderr: self.include_stderr,
                };

                let transform =
                    VectorRemapTransform::from(record.clone(), *job, key.clone(), is_bn);

                let mut source_map = HashMap::new();
                source_map.insert(key.clone(), Box::new(source) as Box<dyn VectorSource>);

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
struct VectorExecSource {
    #[serde(rename = "type")]
    _type: String,
    command: Vec<String>,
    mode: String,
    streaming: SourceStreamingWrapper,
    include_stderr: bool,
}

impl VectorSource for VectorExecSource {
    fn clone_dyn(&self) -> Box<dyn VectorSource> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone, Serialize)]
struct SourceStreamingWrapper {
    respawn_on_exit: bool,
}
