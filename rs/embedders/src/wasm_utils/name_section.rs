//! Removes the parameter-name subsections from the `name` sections of a Wasm
//! module.

use std::borrow::Cow;

/// The magic number and version of a Wasm module.
const MODULE_HEADER: &[u8] = b"\0asm\x01\0\0\0";

const CUSTOM_SECTION_ID: u8 = 0;

const NAME_SECTION_NAME: &[u8] = b"name";

/// The ids of the `name` subsections with the parameter names of function
/// types (12) and of tag types (13).
const PARAMETER_NAMES_SUBSECTION_IDS: [u8; 2] = [12, 13];

/// Returns `wasm` without the subsections 12 (parameter names of function
/// types) and 13 (parameter names of tag types) of its `name` sections.
///
/// These names are not needed to validate, instrument or compile the module,
/// and removing them before Wirm parses it keeps their content from affecting
/// whether the module is accepted. All other bytes stay as they are, except
/// that each changed `name` section gets its new size. If a subsection of a
/// `name` section cannot be walked, that subsection and the rest of the section
/// are kept as they are, so they fail to parse as they would in `wasm`.
///
/// Returns `wasm` itself, without copying, if it has no such subsection or if
/// its sections cannot be walked.
pub(super) fn remove_parameter_name_subsections(wasm: &[u8]) -> Cow<'_, [u8]> {
    match without_parameter_name_subsections(wasm) {
        Some(stripped) => Cow::Owned(stripped),
        None => Cow::Borrowed(wasm),
    }
}

/// Returns `None` if `wasm` has no parameter-name subsection or if its
/// sections cannot be walked.
fn without_parameter_name_subsections(wasm: &[u8]) -> Option<Vec<u8>> {
    let mut rest = wasm.strip_prefix(MODULE_HEADER)?;
    // The bytes of `wasm` before `rest`, with the subsections removed. Only
    // created once a section has a subsection to remove.
    let mut stripped: Option<Vec<u8>> = None;
    while !rest.is_empty() {
        let (section, after) = split_section(rest)?;
        match section {
            Section::Name { name, subsections } if has_parameter_names(subsections) => {
                let stripped = stripped.get_or_insert_with(|| {
                    let mut stripped = Vec::with_capacity(wasm.len());
                    stripped.extend_from_slice(&wasm[..wasm.len() - rest.len()]);
                    stripped
                });
                push_name_section(stripped, name, subsections);
            }
            Section::Name { .. } | Section::Other => {
                if let Some(stripped) = &mut stripped {
                    stripped.extend_from_slice(&rest[..rest.len() - after.len()]);
                }
            }
        }
        rest = after;
    }
    stripped
}

enum Section<'a> {
    /// A custom section named `name`: its encoded name (length and bytes) and
    /// the subsections after it.
    Name {
        name: &'a [u8],
        subsections: &'a [u8],
    },
    Other,
}

/// Splits the section at the start of `bytes` from the bytes after it.
fn split_section(bytes: &[u8]) -> Option<(Section<'_>, &[u8])> {
    let (&id, after_id) = bytes.split_first()?;
    let (size, after_size) = read_leb128_u32(after_id)?;
    let (payload, after) = after_size.split_at_checked(size)?;
    if id != CUSTOM_SECTION_ID {
        return Some((Section::Other, after));
    }
    let (name_len, after_name_len) = read_leb128_u32(payload)?;
    let (name, subsections) = after_name_len.split_at_checked(name_len)?;
    if name != NAME_SECTION_NAME {
        return Some((Section::Other, after));
    }
    let name = &payload[..payload.len() - subsections.len()];
    Some((Section::Name { name, subsections }, after))
}

/// Iterates over the subsections of a `name` section as their id and their
/// bytes (id, size and payload). If a subsection cannot be walked, the last
/// item is the bytes from that subsection to the end, without an id.
fn subsections_of(mut subsections: &[u8]) -> impl Iterator<Item = (Option<u8>, &[u8])> {
    std::iter::from_fn(move || {
        if subsections.is_empty() {
            return None;
        }
        Some(match split_subsection(subsections) {
            Some((id, subsection, after)) => {
                subsections = after;
                (Some(id), subsection)
            }
            None => (None, std::mem::take(&mut subsections)),
        })
    })
}

/// Splits the subsection at the start of `bytes` from the bytes after it.
fn split_subsection(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&id, after_id) = bytes.split_first()?;
    let (size, after_size) = read_leb128_u32(after_id)?;
    let (_payload, after) = after_size.split_at_checked(size)?;
    Some((id, &bytes[..bytes.len() - after.len()], after))
}

fn is_parameter_names(id: Option<u8>) -> bool {
    id.is_some_and(|id| PARAMETER_NAMES_SUBSECTION_IDS.contains(&id))
}

fn has_parameter_names(subsections: &[u8]) -> bool {
    subsections_of(subsections).any(|(id, _)| is_parameter_names(id))
}

/// Appends a `name` section with the encoded `name` and the given subsections
/// except the parameter-name subsections.
fn push_name_section(out: &mut Vec<u8>, name: &[u8], subsections: &[u8]) {
    let kept = || {
        subsections_of(subsections)
            .filter(|(id, _)| !is_parameter_names(*id))
            .map(|(_, subsection)| subsection)
    };
    let size = name.len() + kept().map(<[u8]>::len).sum::<usize>();
    out.push(CUSTOM_SECTION_ID);
    push_leb128(out, size);
    out.extend_from_slice(name);
    for subsection in kept() {
        out.extend_from_slice(subsection);
    }
}

/// Reads an unsigned LEB128 `u32` from the start of `bytes` like wasmparser
/// does: at most 5 bytes, of which the 5th may only use its low 4 bits.
/// Returns the value and the bytes after it.
fn read_leb128_u32(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let mut value = 0_usize;
    for (i, &byte) in bytes.iter().take(5).enumerate() {
        if i == 4 && byte >> 4 != 0 {
            return None;
        }
        value |= usize::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, &bytes[i + 1..]));
        }
    }
    None
}

/// Appends `value` in the shortest unsigned LEB128 encoding.
fn push_leb128(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a section, or a subsection, with the given id and payload.
    fn section(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![id];
        push_leb128(&mut bytes, payload.len());
        bytes.extend_from_slice(payload);
        bytes
    }

    /// The encoded name of a `name` section.
    fn encoded_name() -> Vec<u8> {
        [&[4][..], NAME_SECTION_NAME].concat()
    }

    fn name_section(subsections: &[Vec<u8>]) -> Vec<u8> {
        section(
            CUSTOM_SECTION_ID,
            &[encoded_name(), subsections.concat()].concat(),
        )
    }

    fn module(sections: &[Vec<u8>]) -> Vec<u8> {
        [MODULE_HEADER.to_vec(), sections.concat()].concat()
    }

    /// The type, function and code sections of `(module (func (param i32)))`.
    fn type_function_code_sections() -> [Vec<u8>; 3] {
        [
            section(1, &[1, 0x60, 1, 0x7f, 0]),
            section(3, &[1, 0]),
            section(10, &[1, 2, 0, 0x0b]),
        ]
    }

    /// Subsection 1, naming function 0.
    fn function_names() -> Vec<u8> {
        section(1, &[1, 0, 1, b'f'])
    }

    /// Subsection 12 or 13, naming parameter 0 of type 0.
    fn parameter_names(id: u8) -> Vec<u8> {
        section(id, &[1, 0, 1, 0, 1, b'p'])
    }

    fn assert_unchanged(wasm: &[u8]) {
        let result = remove_parameter_name_subsections(wasm);
        assert!(
            matches!(result, Cow::Borrowed(bytes) if std::ptr::eq(bytes, wasm)),
            "expected the input itself, got {result:?}"
        );
    }

    fn assert_stripped(wasm: &[u8], expected: &[u8]) {
        let result = remove_parameter_name_subsections(wasm);
        assert!(matches!(result, Cow::Owned(_)));
        assert_eq!(&*result, expected);
    }

    #[test]
    fn module_without_name_section_is_unchanged() {
        let [types, functions, code] = type_function_code_sections();
        assert_unchanged(&module(&[]));
        assert_unchanged(&module(&[types, functions, code]));
        // A custom section with another name.
        assert_unchanged(&module(&[section(0, b"\x04namf\x0c\x01\x00")]));
    }

    #[test]
    fn name_section_without_parameter_names_is_unchanged() {
        let [types, functions, code] = type_function_code_sections();
        let module_name = section(0, &[1, b'm']);
        let local_names = section(2, &[1, 0, 1, 0, 1, b'x']);
        let unknown = section(14, &[1, 2, 3]);
        assert_unchanged(&module(&[
            types,
            functions,
            code,
            name_section(&[module_name, function_names(), local_names, unknown]),
        ]));
        assert_unchanged(&module(&[name_section(&[])]));
    }

    #[test]
    fn parameter_names_are_removed() {
        let [types, functions, code] = type_function_code_sections();
        let module_name = section(0, &[1, b'm']);
        let local_names = section(2, &[1, 0, 1, 0, 1, b'x']);
        let expected = module(&[
            types.clone(),
            functions.clone(),
            code.clone(),
            name_section(&[module_name.clone(), function_names(), local_names.clone()]),
        ]);
        for ids in [vec![12], vec![13], vec![12, 13], vec![13, 12, 12]] {
            let mut subsections = vec![module_name.clone(), function_names()];
            subsections.extend(ids.into_iter().map(parameter_names));
            subsections.push(local_names.clone());
            assert_stripped(
                &module(&[
                    types.clone(),
                    functions.clone(),
                    code.clone(),
                    name_section(&subsections),
                ]),
                &expected,
            );
        }
        assert_stripped(
            &module(&[name_section(&[parameter_names(12), parameter_names(13)])]),
            &module(&[name_section(&[])]),
        );
    }

    #[test]
    fn malformed_parameter_names_are_removed() {
        // Parameter 0 of type 0 named by the byte 0xff, which is not UTF-8,
        // and a name map that declares more names than it holds.
        for payload in [&[1, 0, 1, 0, 1, 0xff][..], &[1, 0, 9]] {
            assert_stripped(
                &module(&[name_section(&[function_names(), section(12, payload)])]),
                &module(&[name_section(&[function_names()])]),
            );
        }
    }

    #[test]
    fn section_size_is_re_encoded() {
        let long_function_names = section(1, &[&[1, 0, 0x7f][..], &[b'f'; 0x7f]].concat());
        // The size of the section goes from two bytes to one, stays at two
        // bytes, and goes from three bytes to two.
        for (kept, removed) in [
            (function_names(), section(12, &[0; 200])),
            (long_function_names.clone(), section(12, &[0; 200])),
            (long_function_names, section(12, &[0; 20_000])),
        ] {
            assert_stripped(
                &module(&[name_section(&[kept.clone(), removed])]),
                &module(&[name_section(&[kept])]),
            );
        }
    }

    #[test]
    fn padded_sizes_are_read() {
        // Sizes in the longest encoding that wasmparser accepts: 5 bytes.
        let padded = |size: usize| [0x80 | u8::try_from(size).unwrap(), 0x80, 0x80, 0x80, 0];
        let function_names = [&[1][..], &padded(4), &[1, 0, 1, b'f']].concat();
        let parameter_names = [&[12][..], &padded(6), &[1, 0, 1, 0, 1, b'p']].concat();
        // The name with its length in 2 bytes.
        let name = [&[0x84, 0][..], NAME_SECTION_NAME].concat();
        let payload = [&name[..], &function_names, &parameter_names].concat();
        assert_stripped(
            &module(&[[&[0][..], &padded(payload.len()), &payload].concat()]),
            &module(&[section(0, &[&name[..], &function_names].concat())]),
        );
    }

    #[test]
    fn malformed_modules_are_unchanged() {
        let sections = name_section(&[function_names(), parameter_names(12)]);
        let wasm = [MODULE_HEADER, &sections].concat();
        // A component, and a module of another version.
        assert_unchanged(&[&b"\0asm\x0d\0\x01\0"[..], &sections].concat());
        assert_unchanged(&[&b"\0asm\x02\0\0\0"[..], &sections].concat());
        // Cut off at every byte after the header.
        for len in MODULE_HEADER.len() + 1..wasm.len() {
            assert_unchanged(&wasm[..len]);
        }
        // A section after the `name` section is cut off, has a size past the
        // end, or a size encoding that wasmparser rejects: too long, or too
        // large for a `u32`.
        for malformed in [
            &[1][..],
            &[1, 0x80],
            &[1, 1],
            &[1, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
            &[1, 0x80, 0x80, 0x80, 0x80, 0x10],
        ] {
            assert_unchanged(&[&wasm[..], malformed].concat());
        }
        // A custom section whose name is longer than the section.
        assert_unchanged(&[&wasm[..], &[0, 2, 5, b'n']].concat());
    }

    #[test]
    fn malformed_subsections_are_kept() {
        let head = [encoded_name(), function_names()].concat();
        let too_long_size = [1, 0x80, 0x80, 0x80, 0x80, 0x80, 0];
        // A subsection whose size is past the end of the section, whose size
        // encoding is cut off by the end of the section, or is too long.
        for tail in [
            [&[1, 0x7f, 0][..], &parameter_names(13)].concat(),
            vec![1, 0x80],
            [&too_long_size[..], &parameter_names(13)].concat(),
        ] {
            let expected = module(&[section(0, &[&head[..], &tail].concat())]);
            assert_unchanged(&expected);
            // Parameter names before the malformed subsection are removed. The
            // malformed subsection and everything after it are kept.
            assert_stripped(
                &module(&[section(
                    0,
                    &[&head[..], &parameter_names(12), &tail].concat(),
                )]),
                &expected,
            );
        }
        // Parameter names whose size is past the end of the section.
        assert_unchanged(&module(&[section(0, &[&head[..], &[12, 9, 0]].concat())]));
    }

    #[test]
    fn every_name_section_is_stripped() {
        let [types, functions, code] = type_function_code_sections();
        let stripped = name_section(&[function_names()]);
        assert_stripped(
            &module(&[
                types.clone(),
                functions.clone(),
                code.clone(),
                name_section(&[function_names(), parameter_names(12)]),
                stripped.clone(),
                name_section(&[parameter_names(13), function_names()]),
            ]),
            &module(&[
                types,
                functions,
                code,
                stripped.clone(),
                stripped.clone(),
                stripped,
            ]),
        );
    }

    #[test]
    fn name_section_before_code_section_is_stripped() {
        let [types, functions, code] = type_function_code_sections();
        assert_stripped(
            &module(&[
                types.clone(),
                functions.clone(),
                name_section(&[function_names(), parameter_names(12)]),
                code.clone(),
            ]),
            &module(&[types, functions, name_section(&[function_names()]), code]),
        );
    }
}
