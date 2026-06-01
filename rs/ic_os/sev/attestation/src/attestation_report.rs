use sev::Generation;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;
use std::io::Result;

pub trait AttestationReportExt {
    /// Returns the SEV generation inferred from the report's CPUID fields.
    fn generation(&self) -> Result<Generation>;

    /// Returns the launch TCB encoded as a raw `u64`.
    fn launch_tcb_as_u64(&self) -> Result<u64>;

    /// Returns the reported TCB encoded as a raw `u64`.
    fn reported_tcb_as_u64(&self) -> Result<u64>;

    /// Returns the committed TCB encoded as a raw `u64`.
    fn committed_tcb_as_u64(&self) -> Result<u64>;

    /// Returns the current TCB encoded as a raw `u64`.
    fn current_tcb_as_u64(&self) -> Result<u64>;
}

impl AttestationReportExt for AttestationReport {
    fn generation(&self) -> Result<Generation> {
        Generation::identify_cpu(
            self.cpuid_fam_id.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "cpuid_fam_id is missing")
            })?,
            self.cpuid_mod_id.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "CPUID model ID is missing")
            })?,
        )
    }

    fn launch_tcb_as_u64(&self) -> Result<u64> {
        tcb_version_to_u64(self.launch_tcb, self.generation()?)
    }

    fn reported_tcb_as_u64(&self) -> Result<u64> {
        tcb_version_to_u64(self.reported_tcb, self.generation()?)
    }

    fn committed_tcb_as_u64(&self) -> Result<u64> {
        tcb_version_to_u64(self.committed_tcb, self.generation()?)
    }

    fn current_tcb_as_u64(&self) -> Result<u64> {
        tcb_version_to_u64(self.current_tcb, self.generation()?)
    }
}

/// Converts a `TcbVersion` to its raw `u64` representation (little-endian layout
/// matching the AMD SEV-SNP ABI).
pub fn tcb_version_to_u64(tcb: TcbVersion, generation: Generation) -> Result<u64> {
    let bytes: [u8; 8] = tcb.to_bytes_with(generation)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation_testing::attestation_report::AttestationReportBuilder;

    #[test]
    fn reported_tcb_as_u64_matches_raw_report_bytes() {
        let report = AttestationReportBuilder::new()
            .with_reported_tcb(TcbVersion::new(Some(42), 11, 22, 33, 44))
            .build_unsigned();
        let report_bytes = report.to_bytes().unwrap();
        let tcb_u64 = report.reported_tcb_as_u64().unwrap();
        let reported_tcb_in_report = &report_bytes[0x180..0x188];

        assert_eq!(&tcb_u64.to_bytes().unwrap(), reported_tcb_in_report);
    }

    #[test]
    fn launch_tcb_as_u64_matches_launch_tcb_field() {
        let launch_tcb = TcbVersion::new(Some(7), 1, 2, 3, 4);
        let report = AttestationReportBuilder::new()
            .with_launch_tcb(launch_tcb)
            .build_unsigned();

        assert_eq!(
            report.launch_tcb_as_u64().unwrap(),
            tcb_version_to_u64(launch_tcb, Generation::Milan).unwrap()
        );
    }

    #[test]
    fn generation_fails_when_cpuid_fields_are_missing() {
        let mut report = AttestationReportBuilder::new().build_unsigned();
        report.cpuid_fam_id = None;

        let err = match report.generation() {
            Ok(_) => panic!("generation() should fail when cpuid_fam_id is missing"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("cpuid_fam_id is missing"));
    }
}
