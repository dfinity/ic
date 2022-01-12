// Utilities to collect OS metrics from processes.

// Returns the resident set size of the given process for all data that is not
// shared with other processes (= "RSSAnon"). This is the amount of memory
// used privately by the process, subtracting all shared code, libraries and
// other shared mappings.
//
// The size is returned in Kib units.
pub fn get_nonshared_rss(pid: u32) -> std::io::Result<u64> {
    let path = std::path::Path::new("/proc")
        .join(pid.to_string())
        .join("status");
    let data = std::fs::read(path)?;
    let fields = parse_proc_status(&data);

    let rss_anon = get_named_field_kb(&fields, "RssAnon")?;

    Ok(rss_anon)
}

// Helpers for parsing contents of /proc files below.

// Parse the contents of /proc/<pid>/status as key/value pairs. Note that
// input must be assumed to be u8 because there are no guarantees that the
// contents are valid utf8 (in particular the "name" portion). We can only
// assume that about the keys which are from a fixed known set.
fn parse_proc_status(data: &[u8]) -> std::collections::HashMap<String, Vec<u8>> {
    // Format of input is: [Key] ":" [whitespace] [value] "\n".
    // Parse it char-by-char using simple state machine.
    enum ParseState {
        Key,
        Separator,
        Value,
    }

    let mut fields = std::collections::HashMap::<String, Vec<u8>>::new();
    let mut parse_state = ParseState::Key;
    let mut current_key = Vec::<u8>::new();
    let mut current_value = Vec::<u8>::new();

    for ch in data {
        match parse_state {
            ParseState::Key => {
                if *ch == b':' {
                    parse_state = ParseState::Separator;
                } else {
                    current_key.push(*ch);
                }
            }
            ParseState::Separator => {
                if *ch != b' ' && *ch != b'\t' {
                    parse_state = ParseState::Value;
                    current_value.push(*ch);
                } else if *ch == b'\n' {
                    // Keys are always ascii, hence valid utf8, so this
                    // always succeeds. Formally, ignore malformed field names.
                    if let Ok(key) = std::str::from_utf8(&current_key) {
                        fields.insert(key.to_string(), std::mem::take(&mut current_value));
                        current_key.clear();
                    }
                }
            }
            ParseState::Value => {
                if *ch == b'\n' {
                    if let Ok(key) = std::str::from_utf8(&current_key) {
                        fields.insert(key.to_string(), std::mem::take(&mut current_value));
                        current_key.clear();
                    }
                    parse_state = ParseState::Key;
                } else {
                    current_value.push(*ch);
                }
            }
        }
    }

    fields
}

// From the given key/value map, extracts the named field. The value must be
// of the form "[num] kB", and the numeric value is returned.
fn get_named_field_kb(
    fields: &std::collections::HashMap<String, Vec<u8>>,
    name: &str,
) -> std::io::Result<u64> {
    if let Some(rss_anon) = fields.get(name) {
        let re = regex::Regex::new(r"([0-9]+)[ \t]+kB").unwrap();
        if let Ok(rss_anon_str) = std::str::from_utf8(rss_anon) {
            if let Some(caps) = re.captures(rss_anon_str) {
                if let Some(size_str) = caps.get(1) {
                    if let Ok(size) = size_str.as_str().parse::<u64>() {
                        return Ok(size);
                    }
                }
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Parsing RSS information from process",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTCASE: &str = r#" Name:   cat
Umask:  0002
State:  R (running)
Tgid:   44572
Ngid:   0
Pid:    44572
PPid:   44546
TracerPid:      0
Uid:    1000    1000    1000    1000
Gid:    1000    1000    1000    1000
FDSize: 256
Groups: 4 24 27 30 46 120 131 132 135 1000
NStgid: 44572
NSpid:  44572
NSpgid: 44572
NSsid:  44546
VmPeak:     8588 kB
VmSize:     8588 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:       716 kB
VmRSS:       716 kB
RssAnon:              72 kB
RssFile:             644 kB
RssShmem:              0 kB
VmData:      316 kB
VmStk:       132 kB
VmExe:        20 kB
VmLib:      1652 kB
VmPTE:        48 kB
VmSwap:        0 kB
HugetlbPages:          0 kB
CoreDumping:    0
THP_enabled:    1
Threads:        1
SigQ:   0/55047
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: 0000000000000000
SigCgt: 0000000000000000
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Seccomp_filters:        0
Speculation_Store_Bypass:       thread vulnerable
SpeculationIndirectBranch:      conditional enabled
Cpus_allowed:   00ff
Cpus_allowed_list:      0-7
Mems_allowed:   00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        0
nonvoluntary_ctxt_switches:     0
}"#;

    #[test]
    fn test_parse_and_extract_value() {
        let fields = parse_proc_status(TESTCASE.as_bytes());
        assert_eq!(get_named_field_kb(&fields, "RssAnon").unwrap(), 72);
    }
}
