use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::fmt;
use std::fs;

use crate::prometheus_metric::{LabelPair, MetricType, PrometheusMetric};

#[derive(Eq, PartialEq, Debug)]
pub enum HardwareGen {
    Gen1,
    Gen2,
    Unknown,
}

impl fmt::Display for HardwareGen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: String = match self {
            HardwareGen::Gen1 => "Gen1".into(),
            HardwareGen::Gen2 => "Gen2".into(),
            HardwareGen::Unknown => "GenUnknown".into(),
        };
        write!(f, "{}", s)
    }
}

/// Given the cpu model line from /proc/cpuinfo, parse and return node generation.
fn parse_hardware_gen(cpu_model_line: &str) -> Result<HardwareGen> {
    let re = Regex::new(r"model name\s*:\s*AMD\s*EPYC\s+(\S+)\s+(\S+)\s+(\S+)")?;
    let captures = re
        .captures(cpu_model_line)
        .with_context(|| format!("Detected non-AMD CPU: {}", cpu_model_line))?;

    let epyc_model_number = captures
        .get(1)
        .with_context(|| format!("Could not parse AMD EPYC model number: {}", cpu_model_line))?;
    let epyc_model_number = epyc_model_number.as_str();

    match epyc_model_number.chars().last() {
        Some('2') => Ok(HardwareGen::Gen1),
        Some('3') => Ok(HardwareGen::Gen2),
        Some(_) => {
            eprintln!(
                "CPU model other than EPYC Rome or Milan: {}",
                cpu_model_line
            );
            Ok(HardwareGen::Unknown)
        }
        None => Err(anyhow!(
            "Could not parse AMD EPYC model number: {}",
            epyc_model_number
        )),
    }
}

fn get_cpu_model_string() -> Result<String> {
    let cpu_info = fs::read_to_string("/proc/cpuinfo")?;
    cpu_info
        .lines()
        .find(|line| line.starts_with("model name"))
        .map(|line| line.to_string())
        .ok_or(anyhow!("Error parsing cpu info: {}", cpu_info))
}

fn get_node_gen() -> Result<HardwareGen> {
    let cpu_model_line = get_cpu_model_string()?;
    println!("Found CPU model: {cpu_model_line}");
    parse_hardware_gen(&cpu_model_line)
}

/// Gather CPU info and return CPU metric
/// Sample output:
/// """
/// # HELP node_hardware_generation Generation of Node Hardware
/// # TYPE node_hardware_generation gauge
/// node_hardware_generation{gen="Gen1"} 0
/// """
pub fn get_node_gen_metric() -> PrometheusMetric {
    let gen = match get_node_gen() {
        Ok(gen) => gen,
        Err(e) => {
            eprintln!("Error getting node gen: {e}");
            HardwareGen::Unknown
        }
    };

    let gen_string = gen.to_string();
    println!("Determined node generation: {gen_string}");

    let metric_value = match gen {
        HardwareGen::Unknown => 0.0,
        _ => 1.0,
    };

    PrometheusMetric {
        name: "node_hardware_generation".into(),
        help: "Generation of Node Hardware".into(),
        metric_type: MetricType::Gauge,
        labels: [LabelPair {
            label: "gen".into(),
            value: gen_string.clone(),
        }]
        .to_vec(),
        value: metric_value,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_parse_hardware_gen() {
        assert_eq!(
            parse_hardware_gen("model name : AMD EPYC 7302 16-Core Processor").unwrap(),
            HardwareGen::Gen1
        );
        assert_eq!(
            parse_hardware_gen("model name      : AMD EPYC 7313 32-Core Processor").unwrap(),
            HardwareGen::Gen2
        );
        assert_eq!(
            parse_hardware_gen("model name      : AMD EPYC 7543 32-Core Processor").unwrap(),
            HardwareGen::Gen2
        );
        assert!(
            parse_hardware_gen("model name      : Intel Fake Lake i5-1040 32-Core Processor")
                .is_err()
        );
        assert!(parse_hardware_gen("Fast times at Ridgemont High").is_err());
        assert!(parse_hardware_gen("").is_err());
    }
}
