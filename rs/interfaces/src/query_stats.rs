#[derive(Debug)]
pub enum QueryStatsPermanentValidationError {}

#[derive(Debug)]
pub enum QueryStatsTransientValidationError {
    /// The feature is not enabled
    Disabled,
}
