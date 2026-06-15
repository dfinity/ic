//! Tool: returns the current UTC date/time. Useful for time-sensitive
//! prompts.

use chrono::Utc;
use rig::{completion::ToolDefinition, tool::Tool};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct CurrentDateTimeArgs {}

#[derive(Debug, Serialize)]
pub struct CurrentDateTimeOutput {
    pub utc: String,
    pub unix_seconds: i64,
}

#[derive(Debug, thiserror::Error)]
#[error("current_datetime tool: {0}")]
pub struct CurrentDateTimeError(String);

pub struct CurrentDateTime;

impl Tool for CurrentDateTime {
    const NAME: &'static str = "current_datetime";
    type Error = CurrentDateTimeError;
    type Args = CurrentDateTimeArgs;
    type Output = CurrentDateTimeOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Returns the current UTC date and time, plus the corresponding Unix \
                timestamp in seconds. Takes no arguments."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }

    async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
        let now = Utc::now();
        Ok(CurrentDateTimeOutput {
            utc: now.to_rfc3339(),
            unix_seconds: now.timestamp(),
        })
    }
}
