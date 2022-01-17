use lazy_static::lazy_static;

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
                    parse_state = ParseState::Value;
                } else {
                    current_key.push(*ch);
                }
            }
            ParseState::Value => {
                if *ch == b'\n' {
                    // Keys are always ascii, hence valid utf8, so this
                    // always succeeds. Formally, ignore malformed field names.
                    let value = std::mem::take(&mut current_value);
                    if let Ok(key) = std::str::from_utf8(&current_key) {
                        fields.insert(key.to_string(), value);
                    }
                    current_key.clear();
                    parse_state = ParseState::Key;
                } else if (*ch != b' ' && *ch != b'\t') || !current_value.is_empty() {
                    // Add to value buffer, but skip whitespace at the beginning.
                    current_value.push(*ch);
                }
            }
        }
    }

    fields
}

// Info about a single VMA, taken from /proc/<pid>/smaps
pub struct VMAInfo {
    pub address_range: Vec<u8>,
    pub protection: Vec<u8>,
    pub offset: Vec<u8>,
    pub dev: Vec<u8>,
    pub inode: Vec<u8>,
    pub pathname: Vec<u8>,
    pub fields: std::collections::HashMap<String, Vec<u8>>,
}

impl VMAInfo {
    fn try_parse(data: &[u8]) -> Option<Self> {
        enum ParseState {
            Field,
            Whitespace,
        }

        let mut fields = Vec::<Vec<u8>>::new();
        let mut current_field = Vec::<u8>::new();
        let mut parse_state = ParseState::Field;
        for ch in data {
            match parse_state {
                ParseState::Field => {
                    // whitespace is a field separator, except for last field
                    if (*ch == b' ' || *ch == b'\t') && fields.len() <= 4 {
                        fields.push(std::mem::take(&mut current_field));
                        parse_state = ParseState::Whitespace;
                    } else {
                        current_field.push(*ch);
                    }
                }
                ParseState::Whitespace => {
                    if *ch != b' ' && *ch != b'\t' {
                        current_field.push(*ch);
                        parse_state = ParseState::Field;
                    }
                }
            }
        }
        if let ParseState::Field = parse_state {
            fields.push(std::mem::take(&mut current_field));
        }

        if fields.len() == 6 {
            Some(VMAInfo {
                address_range: std::mem::take(&mut fields[0]),
                protection: std::mem::take(&mut fields[1]),
                offset: std::mem::take(&mut fields[2]),
                dev: std::mem::take(&mut fields[3]),
                inode: std::mem::take(&mut fields[4]),
                pathname: std::mem::take(&mut fields[5]),
                fields: std::collections::HashMap::new(),
            })
        } else {
            None
        }
    }
}

// Parse the contents of /proc/<pid>/smaps and build VMAInfo structures out
// of it.
pub fn parse_proc_smaps(data: &[u8]) -> Vec<VMAInfo> {
    enum ParseState {
        HeaderLineOrKey,
        HeaderLine,
        Value,
    }

    let mut vmas = Vec::<VMAInfo>::new();

    let mut parse_state = ParseState::HeaderLineOrKey;
    let mut current_key = Vec::<u8>::new();
    let mut current_value = Vec::<u8>::new();
    let mut current_vma_info: Option<VMAInfo> = None;
    for ch in data {
        match parse_state {
            ParseState::HeaderLineOrKey => {
                if *ch == b':' {
                    parse_state = ParseState::Value;
                } else if *ch == b' ' {
                    current_key.push(*ch);
                    parse_state = ParseState::HeaderLine;
                } else if *ch == b'\n' {
                    // This line could not be parsed. Ignore and hope for the
                    // best.
                    current_key.clear();
                } else {
                    current_key.push(*ch);
                }
            }
            ParseState::HeaderLine => {
                if *ch == b'\n' {
                    if let Some(vma_info) = current_vma_info.take() {
                        vmas.push(vma_info);
                    }
                    current_vma_info = VMAInfo::try_parse(&current_key);
                    current_key.clear();
                    parse_state = ParseState::HeaderLineOrKey;
                } else {
                    current_key.push(*ch);
                }
            }
            ParseState::Value => {
                if *ch == b'\n' {
                    // Keys are always ascii, hence valid utf8, so this
                    // always succeeds. Formally, ignore malformed field names.
                    let value = std::mem::take(&mut current_value);
                    if let Ok(key) = std::str::from_utf8(&current_key) {
                        if let Some(vma_info) = current_vma_info.as_mut() {
                            vma_info.fields.insert(key.to_string(), value);
                        }
                    }
                    current_key.clear();
                    parse_state = ParseState::HeaderLineOrKey;
                } else if (*ch != b' ' && *ch != b'\t') || !current_value.is_empty() {
                    // Add to value buffer, but skip whitespace at the beginning.
                    current_value.push(*ch);
                }
            }
        }
    }
    if let Some(vma_info) = current_vma_info.take() {
        vmas.push(vma_info);
    }

    vmas
}

fn compute_memfd_rss_total(vma_infos: &[VMAInfo]) -> u64 {
    let mut total: u64 = 0;
    for vma_info in vma_infos {
        const PREFIX: &[u8] = b"/memfd:";
        let matching = vma_info
            .pathname
            .iter()
            .zip(PREFIX.iter())
            .filter(|&(x, y)| x == y)
            .count();
        if matching == PREFIX.len() {
            if let Ok(size) = get_named_field_kb(&vma_info.fields, "Rss") {
                total += size;
            }
        }
    }

    total
}

// Extract the RSS of all memfd regions set up in given process. These regions
// are used to hold the canister and stable memory in RAM and need to be
// accounted for to get an overall view of system resource usage.
pub fn get_memfd_rss(pid: u32) -> std::io::Result<u64> {
    let path = std::path::Path::new("/proc")
        .join(pid.to_string())
        .join("smaps");
    let data = std::fs::read(path)?;
    let vma_infos = parse_proc_smaps(&data);

    Ok(compute_memfd_rss_total(&vma_infos))
}

lazy_static! {
    static ref MEMORY_KIB_PARSE_RE: regex::Regex = regex::Regex::new(r"([0-9]+)[ \t]+kB").unwrap();
}

// From the given key/value map, extracts the named field. The value must be
// of the form "[num] kB", and the numeric value is returned.
fn get_named_field_kb(
    fields: &std::collections::HashMap<String, Vec<u8>>,
    name: &str,
) -> std::io::Result<u64> {
    if let Some(rss_anon) = fields.get(name) {
        if let Ok(rss_anon_str) = std::str::from_utf8(rss_anon) {
            if let Some(caps) = MEMORY_KIB_PARSE_RE.captures(rss_anon_str) {
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

    const PROC_STATUS_TESTCASE: &str = r#" Name:   cat
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

    const PROC_SMAPS_TESTCASE: &str = r#"55c832cfe000-55c832cff000 r--p 00000000 fd:02 3932225                    /tmp/a.out
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         4 kB
Private_Dirty:         0 kB
Referenced:            4 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me dw sd
55c832cff000-55c832d00000 r-xp 00001000 fd:02 3932225                    /tmp/a.out
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         4 kB
Private_Dirty:         0 kB
Referenced:            4 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd ex mr mw me dw sd
55c832d00000-55c832d01000 r--p 00002000 fd:02 3932225                    /tmp/a.out
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         4 kB
Private_Dirty:         0 kB
Referenced:            4 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me dw sd
55c832d01000-55c832d02000 r--p 00002000 fd:02 3932225                    /tmp/a.out
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         4 kB
Referenced:            4 kB
Anonymous:             4 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me dw ac sd
55c832d02000-55c832d03000 rw-p 00003000 fd:02 3932225                    /tmp/a.out
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         4 kB
Referenced:            4 kB
Anonymous:             4 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr mr mw me dw ac sd
7fa09292d000-7fa09296d000 rw-s 00000000 00:01 3505                       /memfd:foo (deleted)
Size:                256 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                 256 kB
Pss:                 256 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:       256 kB
Referenced:          256 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr sh mr mw me ms sd
7fa09296d000-7fa092992000 r--p 00000000 fd:02 6033836                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
Size:                148 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                 136 kB
Pss:                   0 kB
Shared_Clean:        136 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:          136 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me sd
7fa092992000-7fa092b0a000 r-xp 00025000 fd:02 6033836                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
Size:               1504 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                 756 kB
Pss:                  12 kB
Shared_Clean:        748 kB
Shared_Dirty:          0 kB
Private_Clean:         8 kB
Private_Dirty:         0 kB
Referenced:          756 kB
Anonymous:             8 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd ex mr mw me sd
7fa092b0a000-7fa092b54000 r--p 0019d000 fd:02 6033836                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
Size:                296 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                  60 kB
Pss:                   0 kB
Shared_Clean:         60 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:           60 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me sd
7fa092b54000-7fa092b55000 ---p 001e7000 fd:02 6033836                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: mr mw me sd
7fa092b55000-7fa092b58000 r--p 001e7000 fd:02 6033836                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
Size:                 12 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                  12 kB
Pss:                  12 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:        12 kB
Referenced:           12 kB
Anonymous:            12 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me ac sd
7fa092b58000-7fa092b5b000 rw-p 001ea000 fd:02 6033836                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
Size:                 12 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                  12 kB
Pss:                  12 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:        12 kB
Referenced:           12 kB
Anonymous:            12 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr mr mw me ac sd
7fa092b5b000-7fa092b61000 rw-p 00000000 00:00 0
Size:                 24 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                  20 kB
Pss:                  20 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:        20 kB
Referenced:           20 kB
Anonymous:            20 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr mr mw me ac sd
7fa092b7f000-7fa092b80000 r--p 00000000 fd:02 6033832                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   0 kB
Shared_Clean:          4 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            4 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me dw sd
7fa092b80000-7fa092ba3000 r-xp 00001000 fd:02 6033832                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
Size:                140 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                 140 kB
Pss:                   0 kB
Shared_Clean:        140 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:          140 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd ex mr mw me dw sd
7fa092ba3000-7fa092bab000 r--p 00024000 fd:02 6033832                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
Size:                 32 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                  32 kB
Pss:                   0 kB
Shared_Clean:         32 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:           32 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me dw sd
7fa092bac000-7fa092bad000 r--p 0002c000 fd:02 6033832                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         4 kB
Referenced:            4 kB
Anonymous:             4 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me dw ac sd
7fa092bad000-7fa092bae000 rw-p 0002d000 fd:02 6033832                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         4 kB
Referenced:            4 kB
Anonymous:             4 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr mr mw me dw ac sd
7fa092bae000-7fa092baf000 rw-p 00000000 00:00 0
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         4 kB
Referenced:            4 kB
Anonymous:             4 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr mr mw me ac sd
7fff7d6b6000-7fff7d6d7000 rw-p 00000000 00:00 0                          [stack]
Size:                132 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                  16 kB
Pss:                  16 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:        16 kB
Referenced:           16 kB
Anonymous:            16 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr mr mw me gd ac
7fff7d759000-7fff7d75d000 r--p 00000000 00:00 0                          [vvar]
Size:                 16 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr pf io de dd sd
7fff7d75d000-7fff7d75f000 r-xp 00000000 00:00 0                          [vdso]
Size:                  8 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   0 kB
Shared_Clean:          4 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            4 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd ex mr mw me de sd
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: ex
"#;

    #[test]
    fn test_parse_proc_status() {
        let fields = parse_proc_status(PROC_STATUS_TESTCASE.as_bytes());
        assert_eq!(get_named_field_kb(&fields, "RssAnon").unwrap(), 72);
    }

    #[test]
    fn test_parse_smaps() {
        let vmas = parse_proc_smaps(PROC_SMAPS_TESTCASE.as_bytes());
        assert_eq!(vmas[5].pathname, b"/memfd:foo (deleted)");
        assert_eq!(get_named_field_kb(&vmas[5].fields, "Rss").unwrap(), 256);
        assert_eq!(compute_memfd_rss_total(&vmas), 256);
    }
}
