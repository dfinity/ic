use std::fmt;

use itertools::Itertools;
use num_traits::Zero;
use rust_decimal::Decimal;
use trustworthy_node_metrics_types::types::OperationExecutorLog;

pub enum Operation {
    Set(Decimal),
    Sum(Vec<Decimal>),
    Subtract(Decimal, Decimal),
    Multiply(Decimal, Decimal),
    Divide(Decimal, Decimal),
}

impl Operation {
    fn execute(&self) -> Decimal {
        match self {
            Operation::Sum(operators) => operators.iter().cloned().fold(Decimal::zero(), |acc, val| acc + val),
            Operation::Subtract(o1, o2) => o1 - o2,
            Operation::Divide(o1, o2) => o1 / o2,
            Operation::Set(o1) => *o1,
            Operation::Multiply(o1, o2) => o1 * o2,
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (symbol, o1, o2) = match self {
            Operation::Sum(values) => {
                return if values.is_empty() {
                    write!(f, "0")
                } else {
                    write!(
                        f,
                        "{} + {}",
                        values[0],
                        values[1..].iter().map(|o| format!("{}", o.round_dp(4))).collect::<Vec<_>>().join(" + ")
                    )
                }
            }
            Operation::Subtract(o1, o2) => ("-", o1, o2),
            Operation::Divide(o1, o2) => ("/", o1, o2),
            Operation::Set(o1) => return write!(f, "set {}", o1),
            Operation::Multiply(o1, o2) => ("*", o1, o2),
        };
        write!(f, "{} {} {}", o1.round_dp(4), symbol, o2.round_dp(4))
    }
}

pub struct OperationExecutor {
    reason: String,
    operation: Operation,
    result: Decimal,
}

impl OperationExecutor {
    pub fn execute(reason: &str, operation: Operation) -> (Self, Decimal) {
        let result = operation.execute();

        let operation_executed = Self {
            reason: reason.to_string(),
            operation,
            result,
        };

        (operation_executed, result)
    }
}

// Modify ComputationLogger to use NumberEnum
pub struct ComputationLogger {
    pub operations_executed: Vec<OperationExecutor>,
}

impl ComputationLogger {
    pub fn new() -> Self {
        Self {
            operations_executed: Vec::new(),
        }
    }

    pub fn execute(&mut self, reason: &str, operation: Operation) -> Decimal {
        let result = operation.execute();

        let operation_executed = OperationExecutor {
            reason: reason.to_string(),
            operation,
            result,
        };
        self.operations_executed.push(operation_executed);
        result
    }

    pub fn add_executed(&mut self, operations: Vec<OperationExecutor>) {
        for operation in operations {
            self.operations_executed.push(operation)
        }
    }

    pub fn get_log(&self) -> Vec<OperationExecutorLog> {
        self.operations_executed
            .iter()
            .map(|operation_executor| OperationExecutorLog {
                reason: operation_executor.reason.clone(),
                operation: operation_executor.operation.to_string(),
                result: operation_executor.result.to_string(),
            })
            .collect_vec()
    }
}
