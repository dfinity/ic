use anyhow::{Result, ensure};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PartitionSize(u64);

impl PartitionSize {
    pub fn as_kb(&self) -> Result<u64> {
        ensure!(
            self.0.is_multiple_of(1024),
            "Partition size must be a multiple of 1024"
        );

        Ok(self.0 / 1024)
    }
}

impl std::str::FromStr for PartitionSize {
    type Err = String;

    /// Parse a size string like "50M", "1000K", "3G" and return the size in bytes
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let size = s.trim();
        if size.is_empty() {
            return Err("Size string is empty".to_string());
        }

        let (number_part, suffix) = if let Some(pos) = size.find(|c: char| c.is_alphabetic()) {
            (&size[..pos], &size[pos..])
        } else {
            (size, "")
        };

        let number: u64 = number_part
            .parse()
            .map_err(|_| format!("Failed to parse number from: {size}"))?;

        let multiplier = match suffix.to_uppercase().as_str() {
            "" | "B" => 1,
            "K" => 1024,
            "M" => 1024 * 1024,
            "G" => 1024 * 1024 * 1024,
            _ => return Err(format!("Unsupported size suffix: {suffix}")),
        };

        Ok(Self(number * multiplier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size_to_bytes() {
        assert_eq!(
            "50M".parse::<PartitionSize>().unwrap(),
            PartitionSize(50 * 1024 * 1024)
        );
        assert_eq!(
            "1000K".parse::<PartitionSize>().unwrap(),
            PartitionSize(1000 * 1024)
        );
        assert_eq!(
            "3G".parse::<PartitionSize>().unwrap(),
            PartitionSize(3 * 1024 * 1024 * 1024)
        );
        assert_eq!(
            "50m".parse::<PartitionSize>().unwrap(),
            PartitionSize(50 * 1024 * 1024)
        );
        assert_eq!(
            "1000k".parse::<PartitionSize>().unwrap(),
            PartitionSize(1000 * 1024)
        );
        assert_eq!(
            "3g".parse::<PartitionSize>().unwrap(),
            PartitionSize(3 * 1024 * 1024 * 1024)
        );
        assert_eq!(
            "  50M  ".parse::<PartitionSize>().unwrap(),
            PartitionSize(50 * 1024 * 1024)
        );
        assert_eq!("100".parse::<PartitionSize>().unwrap(), PartitionSize(100));

        assert!(("".parse::<PartitionSize>()).is_err());
        assert!(("50T".parse::<PartitionSize>()).is_err());
        assert!(("abc".parse::<PartitionSize>()).is_err());
    }

    #[test]
    fn test_as_kb() {
        assert_eq!(
            "100K".parse::<PartitionSize>().unwrap().as_kb().unwrap(),
            100
        );
        assert_eq!(
            "100M".parse::<PartitionSize>().unwrap().as_kb().unwrap(),
            100 * 1024
        );
        assert!(PartitionSize(100).as_kb().is_err());
    }
}
