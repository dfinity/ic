use crate::{
    CanisterInstallModeV2, SkipPreUpgrade, WasmMemoryPersistence,
    ENHANCED_ORTHOGONAL_PERSISTENCE_SECTION,
};
use candid::Principal;
use hex::decode;

use std::{
    fmt,
    fs::File,
    io::{self, Read},
    str::Chars,
    string::FromUtf8Error,
};

#[derive(Debug, PartialEq)]
pub(crate) enum CanisterInstallMode {
    Install,
    Reinstall,
    Upgrade,
}

#[derive(Debug, PartialEq)]
pub(crate) struct CanisterInstallArgs {
    pub canister_id: Principal,
    pub wasm_module: Vec<u8>,
    pub arg: Vec<u8>,
    pub sender: Principal,
    pub mode: CanisterInstallModeV2,
}

#[derive(Debug, PartialEq)]
pub(crate) struct CanisterCall {
    pub canister_id: Principal,
    pub method_name: String,
    pub arg: Vec<u8>,
    pub sender: Principal,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Message {
    Ingress(CanisterCall),
    Query(CanisterCall),
    Install(CanisterInstallArgs),
    Create,
}

#[derive(Debug)]
pub enum LineIteratorError {
    IoError(io::Error),
    BufferLengthExceeded,
    FromUtf8Error(FromUtf8Error),
}

impl fmt::Display for LineIteratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LineIteratorError::*;

        match self {
            IoError(e) => write!(f, "IO error: {}", e),
            BufferLengthExceeded => write!(f, "Line length exceeds buffer length"),
            FromUtf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
        }
    }
}

const LINE_ITERATOR_BUFFER_SIZE: usize = 16_777_216;

struct LineIterator<R: Read> {
    inner: R,
    buffer: Vec<u8>,
}

impl<R: Read> LineIterator<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: vec![],
        }
    }

    fn split_line(&mut self) -> Option<Result<String, LineIteratorError>> {
        let parts: Vec<_> = self
            .buffer
            .splitn(2, |c| *c == b'\n')
            .map(|slice| slice.to_vec())
            .collect();

        if parts.len() == 1 {
            return None;
        }

        assert!(parts.len() == 2);
        let mut iter = parts.into_iter();
        let line = iter.next().unwrap();
        self.buffer = iter.next().unwrap();
        Some(String::from_utf8(line).map_err(LineIteratorError::FromUtf8Error))
    }
}

impl<R: Read> Iterator for LineIterator<R> {
    type Item = Result<String, LineIteratorError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.buffer.is_empty() {
            let line = self.split_line();

            if line.is_some() {
                return line;
            }
        }

        loop {
            match self
                .inner
                .by_ref()
                .take((LINE_ITERATOR_BUFFER_SIZE - self.buffer.len()) as _)
                .read_to_end(&mut self.buffer)
            {
                Err(e) => return Some(Err(LineIteratorError::IoError(e))),
                Ok(0) => {
                    if self.buffer.is_empty() {
                        return None;
                    }

                    let bytes = self.buffer.clone();
                    self.buffer.clear();
                    return Some(
                        String::from_utf8(bytes).map_err(LineIteratorError::FromUtf8Error),
                    );
                }
                Ok(_) => match self.split_line() {
                    Some(line) => return Some(line),
                    None if self.buffer.len() == LINE_ITERATOR_BUFFER_SIZE => {
                        self.buffer.clear();
                        return Some(Err(LineIteratorError::BufferLengthExceeded));
                    }
                    None => continue,
                },
            }
        }
    }
}

pub(crate) fn msg_stream_from_file(
    filename: &str,
) -> Result<impl Iterator<Item = Result<Message, String>>, String> {
    let f = File::open(filename).map_err(|e| e.to_string())?;
    let line_iterator = LineIterator::new(f);

    Ok(line_iterator
        .enumerate()
        // let's skip commented ('#') and empty lines
        .filter(|(_idx, line)| match line {
            Ok(s) => !s.is_empty() && !s.starts_with('#'),
            _ => true,
        })
        .map(|(i, line)| match line {
            Ok(line) => parse_message(&line).map_err(|e| format!("Line {}: {}", i + 1, e)),
            Err(e) => Err(format!("Error while reading line {}: {}", i, e)),
        }))
}

fn parse_message(s: &str) -> Result<Message, String> {
    let s = s.trim_end();
    let tokens: Vec<&str> = s.splitn(4, char::is_whitespace).collect();

    match &tokens[..] {
        [] => Err("Too few arguments.".to_string()),
        ["ingress", canister_id, method_name, payload] => {
            let canister_id = parse_canister_id(canister_id)?;
            let method_name = validate_method_name(method_name)?;
            let method_payload = parse_octet_string(payload)?;

            Ok(Message::Ingress(CanisterCall {
                canister_id,
                method_name,
                arg: method_payload,
                sender: Principal::anonymous(),
            }))
        }
        ["query", canister_id, method_name, payload] => Ok(Message::Query(CanisterCall {
            sender: Principal::anonymous(),
            canister_id: parse_canister_id(canister_id)?,
            method_name: validate_method_name(method_name)?,
            arg: parse_octet_string(payload)?,
        })),
        ["create"] => parse_create(),
        ["install", canister_id, wasm_file, payload] => parse_install(
            canister_id,
            payload,
            wasm_file,
            CanisterInstallMode::Install,
        ),
        ["reinstall", canister_id, wasm_file, payload] => parse_install(
            canister_id,
            payload,
            wasm_file,
            CanisterInstallMode::Reinstall,
        ),
        ["upgrade", canister_id, wasm_file, payload] => parse_install(
            canister_id,
            payload,
            wasm_file,
            CanisterInstallMode::Upgrade,
        ),
        _ => Err(format!(
            "Failed to parse line {}, don't have a pattern to match this with",
            s
        )),
    }
}

fn parse_canister_id(canister_id: &str) -> Result<Principal, String> {
    match Principal::from_text(canister_id) {
        Ok(id) => Ok(id),
        Err(err) => Err(format!(
            "Failed to convert {} to principal id with {}",
            canister_id, err
        )),
    }
}

fn parse_create() -> Result<Message, String> {
    Ok(Message::Create)
}

fn contains_icp_private_custom_section(wasm_binary: &[u8], name: &str) -> Result<bool, String> {
    use wasmparser::{Parser, Payload::CustomSection};

    let icp_section_name = format!("icp:private {name}");
    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm_binary) {
        if let CustomSection(reader) = payload.map_err(|e| format!("Wasm parsing error: {}", e))? {
            if reader.name() == icp_section_name {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn parse_install(
    canister_id: &str,
    payload: &str,
    wasm_file: &str,
    mode: CanisterInstallMode,
) -> Result<Message, String> {
    let mut wasm_data = Vec::new();
    let mut wasm_file = File::open(wasm_file)
        .map_err(|e| format!("Could not open wasm file: {} - Error: {}", wasm_file, e))?;
    wasm_file
        .read_to_end(&mut wasm_data)
        .map_err(|e| e.to_string())?;

    let canister_id = parse_canister_id(canister_id)?;
    let payload = parse_octet_string(payload)?;

    let install_mode = match mode {
        CanisterInstallMode::Install => CanisterInstallModeV2::Install,
        CanisterInstallMode::Reinstall => CanisterInstallModeV2::Reinstall,
        CanisterInstallMode::Upgrade => {
            let wasm_memory_persistence = if contains_icp_private_custom_section(
                wasm_data.as_ref(),
                ENHANCED_ORTHOGONAL_PERSISTENCE_SECTION,
            )? {
                Some(WasmMemoryPersistence::Keep)
            } else {
                None
            };
            CanisterInstallModeV2::Upgrade(Some(SkipPreUpgrade {
                skip_pre_upgrade: None,
                wasm_memory_persistence,
            }))
        }
    };

    Ok(Message::Install(CanisterInstallArgs {
        canister_id,
        wasm_module: wasm_data,
        arg: payload,
        sender: Principal::anonymous(),
        mode: install_mode,
    }))
}

fn validate_method_name(method_name: &str) -> Result<String, String> {
    fn is_ident_start(c: char) -> bool {
        c.is_ascii() && (c.is_alphabetic() || c == '_')
    }

    fn is_ident_tail(c: char) -> bool {
        c.is_ascii() && (c.is_alphanumeric() || c == '_')
    }

    let mut chars = method_name.chars();
    let is_legal_start = chars.next().map(is_ident_start).unwrap_or(false);
    let is_legal_tail = chars.all(is_ident_tail);

    if !(is_legal_start && is_legal_tail) {
        Err(format!("Illegal method name: {}.", method_name))
    } else {
        Ok(String::from(method_name))
    }
}

fn parse_octet_string(input_str: &str) -> Result<Vec<u8>, String> {
    if input_str.starts_with('"') {
        parse_quoted(input_str)
    } else {
        parse_hex(input_str)
    }
}

fn parse_quoted(quoted_str: &str) -> Result<Vec<u8>, String> {
    if !quoted_str.is_ascii() {
        return Err(String::from("Only ASCII strings are allowed."));
    }

    let mut chars = quoted_str.chars();
    let mut res: Vec<u8> = Vec::new();
    let mut escaped = false;

    if Some('"') != chars.next() {
        return Err(String::from(
            "Double-quoted string must be enclosed in double quotes.",
        ));
    }

    let mut c = chars.next();
    while let Some(cur) = c {
        if escaped {
            let b = match cur {
                'x' => parse_escape(&mut chars, Radix::Hex)?,
                'b' => parse_escape(&mut chars, Radix::Bin)?,
                '"' => b'"',
                '\\' => b'\\',
                _ => return Err(format!("Illegal escape sequence {}", cur)),
            };
            res.push(b);
            escaped = false;
        } else {
            match cur {
                '\\' => escaped = true,
                '"' => {
                    chars.next(); // consume '"'
                    break;
                }
                _ => res.push(cur as u8),
            }
        }
        c = chars.next();
    }

    if chars.next().is_some() {
        return Err(String::from("Trailing characters after string terminator."));
    }

    Ok(res)
}

fn parse_escape(chars: &mut Chars<'_>, radix: Radix) -> Result<u8, String> {
    let len = match radix {
        Radix::Bin => 8,
        Radix::Hex => 2,
    };
    let s = chars.take(len).collect::<String>();
    if s.len() >= len {
        u8::from_str_radix(&s, radix as u32).map_err(|e| e.to_string())
    } else {
        Err(format!(
            "Escape sequence for radix {:?} too short: {}",
            radix, s
        ))
    }
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    if let Some(s) = s.strip_prefix("0x") {
        decode(s).map_err(|e| e.to_string())
    } else {
        Err(format!("Illegal hex character sequence {}.", s))
    }
}

#[derive(Debug)]
enum Radix {
    Bin = 2,
    Hex = 16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_message_quoted_payload_succeeds() {
        let app_canister_id = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
        let s = &format!(
            "ingress {} write \"payload \\x0a\\b00010001\"",
            app_canister_id
        );
        let parsed_message = parse_message(s).unwrap();
        let expected = Message::Ingress(CanisterCall {
            canister_id: app_canister_id,
            method_name: "write".to_string(),
            arg: vec![112, 97, 121, 108, 111, 97, 100, 32, 10, 17],
            sender: Principal::anonymous(),
        });
        assert_eq!(expected, parsed_message);
    }

    #[test]
    fn test_parse_message_hex_payload_succeeds() {
        let app_canister_id = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
        let s = &format!("ingress {} write 0x010203", app_canister_id);
        let parsed_message = parse_message(s).unwrap();
        let expected = Message::Ingress(CanisterCall {
            canister_id: app_canister_id,
            method_name: "write".to_string(),
            arg: vec![1, 2, 3],
            sender: Principal::anonymous(),
        });
        assert_eq!(expected, parsed_message);

        let s = &format!("query {} read 0x010203", app_canister_id);
        let parsed_message = parse_message(s).unwrap();
        let expected = Message::Query(CanisterCall {
            sender: Principal::anonymous(),
            canister_id: app_canister_id,
            method_name: String::from("read"),
            arg: vec![1, 2, 3],
        });
        assert_eq!(expected, parsed_message);
    }

    #[test]
    fn test_parse_message_invalid_escapes_fails() {
        let app_canister_id = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();

        let s = &format!("query {} read \"\\xzz\"", app_canister_id);
        assert!(parse_message(s).is_err());

        let s = &format!("query {} read \"\\b01\"", app_canister_id);
        assert!(parse_message(s).is_err());

        let s = &format!("query {} read \"\\x1\"", app_canister_id);
        assert!(parse_message(s).is_err());

        let s = &format!("query {} read \"\\b2\"", app_canister_id);
        assert!(parse_message(s).is_err());
    }

    #[test]
    fn test_illegal_method_name_must_fail() {
        let app_canister_id = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();

        let s = &format!("query {} 0read \"\\xzz\"", app_canister_id);
        assert!(parse_message(s).is_err());

        let s = &format!("query {} üread \"\\xzz\"", app_canister_id);
        assert!(parse_message(s).is_err());
    }

    #[test]
    fn test_line_iterator() {
        let text = Cursor::new(
            r#"O for a voice like thunder, and a tongue
To drown the throat of war! When the senses
Are shaken, and the soul is driven to madness,
Who can stand?
"#,
        );
        let mut lines = LineIterator::new(text);
        assert_eq!(
            lines.next().unwrap().unwrap(),
            "O for a voice like thunder, and a tongue"
        );
        assert_eq!(
            lines.next().unwrap().unwrap(),
            "To drown the throat of war! When the senses"
        );
        assert_eq!(
            lines.next().unwrap().unwrap(),
            "Are shaken, and the soul is driven to madness,"
        );
        assert_eq!(lines.next().unwrap().unwrap(), "Who can stand?");
        lines.next();
        assert!(lines.next().is_none());
    }

    #[test]
    fn test_line_iterator_no_newline() {
        let text = "O for a voice like thunder, and a tongue";
        let mut lines = LineIterator::new(Cursor::new(text));
        assert_eq!(lines.next().unwrap().unwrap(), text);
        lines.next();
        assert!(lines.next().is_none());
    }

    #[test]
    fn test_line_iterator_line_same_length_as_input_buffer() {
        let mut text = " ".repeat(LINE_ITERATOR_BUFFER_SIZE - 1);
        text.push('\n');
        assert!(text.len() == LINE_ITERATOR_BUFFER_SIZE);
        let mut lines = LineIterator::new(Cursor::new(text));
        let line = lines.next();
        assert!(line.unwrap().is_ok());
        lines.next();
        assert!(lines.next().is_none());
    }

    #[test]
    fn test_line_iterator_line_longer_than_input_buffer() {
        let text = " ".repeat(LINE_ITERATOR_BUFFER_SIZE) + "continuation past the buffer";
        assert!(text.len() > LINE_ITERATOR_BUFFER_SIZE);
        let mut lines = LineIterator::new(Cursor::new(text));
        assert!(lines.next().unwrap().is_err());
        assert_eq!(
            lines.next().unwrap().unwrap(),
            "continuation past the buffer"
        );
        lines.next();
        assert!(lines.next().is_none());
    }
}
