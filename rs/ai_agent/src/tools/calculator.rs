//! Tool: evaluate a basic arithmetic expression with `meval`.

use rig::{completion::ToolDefinition, tool::Tool};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct CalculatorArgs {
    pub expression: String,
}

#[derive(Debug, Serialize)]
pub struct CalculatorOutput {
    pub expression: String,
    pub result: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum CalculatorError {
    #[error("failed to evaluate expression: {0}")]
    Eval(#[from] meval::Error),
}

pub struct Calculator;

impl Tool for Calculator {
    const NAME: &'static str = "calculator";
    type Error = CalculatorError;
    type Args = CalculatorArgs;
    type Output = CalculatorOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Evaluates a basic arithmetic expression and returns the numeric result. \
                Supports +, -, *, /, ^, parentheses, and standard math functions like sin, cos, sqrt."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "An arithmetic expression, e.g. '(144 / 12) * 7'"
                    }
                },
                "required": ["expression"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let result = meval::eval_str(&args.expression)?;
        Ok(CalculatorOutput {
            expression: args.expression,
            result,
        })
    }
}
