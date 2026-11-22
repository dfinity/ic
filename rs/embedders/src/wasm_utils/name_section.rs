//! Removes the `name` subsections that validation and instrumentation ignore.

use std::borrow::Cow;

/// The magic number and version of a Wasm module.
const MODULE_HEADER: &[u8] = b"\0asm\x01\0\0\0";

const CUSTOM_SECTION_ID: u8 = 0;

const NAME_SECTION_NAME: &[u8] = b"name";

/// The ids of the `name` subsections with the parameter names of function
/// types (12) and of tag types (13).
const PARAMETER_NAMES_SUBSECTION_IDS: [u8; 2] = [12, 13];

/// The maximum length in bytes of the module name and of the names in the
/// inner name maps of an indirect name map. The names in the other name maps
/// have no maximum length.
const MAX_NAME_LEN: usize = 100_000;

/// Returns `wasm` without the `name` subsections that validation and
/// instrumentation ignore. In each `name` section, these are:
///
/// - the subsections 12 (parameter names of function types) and 13
///   (parameter names of tag types);
/// - each subsection whose id is not greater than the id of the last
///   subsection kept before it;
/// - each subsection with a name map whose indices are not strictly
///   increasing: the name map of the subsections 1, 4 to 9 and 11, or the
///   outer map or one of the inner maps of the subsections 2, 3 and 10.
///
/// These names are not needed to validate, instrument or compile the module.
/// Wirm parses the `name` section with wasmparser, which rejects subsections
/// and name maps that are out of order, and reads the subsections 12 and 13.
/// Removing these subsections before Wirm parses the module keeps their order,
/// and the content of the subsections 12 and 13, from affecting whether the
/// module is accepted.
///
/// All other bytes stay as they are, except that each changed `name` section
/// gets its new size. The content of the subsections 0 to 11 is parsed as
/// wasmparser parses it. If a subsection cannot be parsed, that subsection and
/// the rest of its section are kept as they are, so that they fail to parse as
/// they would in `wasm`.
///
/// Returns `wasm` itself, without copying, if nothing is removed or if its
/// sections cannot be walked.
pub(super) fn remove_ignored_name_subsections(wasm: &[u8]) -> Cow<'_, [u8]> {
    match without_ignored_name_subsections(wasm) {
        Some(stripped) => Cow::Owned(stripped),
        None => Cow::Borrowed(wasm),
    }
}

/// Returns `None` if nothing is removed or if the sections of `wasm` cannot be
/// walked.
fn without_ignored_name_subsections(wasm: &[u8]) -> Option<Vec<u8>> {
    let mut rest = wasm.strip_prefix(MODULE_HEADER)?;
    // The bytes of `wasm` before `rest`, with the subsections removed. Only
    // created once a section has a subsection to remove.
    let mut stripped: Option<Vec<u8>> = None;
    while !rest.is_empty() {
        let (section, after) = split_section(rest)?;
        // The encoded name, the subsections and the length of the kept
        // subsections of a `name` section with a subsection to remove.
        let changed = match section {
            Section::Name { name, subsections } => {
                let kept_len: usize = kept_subsections(subsections).map(<[u8]>::len).sum();
                (kept_len < subsections.len()).then_some((name, subsections, kept_len))
            }
            Section::Other => None,
        };
        if let Some((name, subsections, kept_len)) = changed {
            let stripped = stripped.get_or_insert_with(|| {
                let mut stripped = Vec::with_capacity(wasm.len());
                stripped.extend_from_slice(&wasm[..wasm.len() - rest.len()]);
                stripped
            });
            stripped.push(CUSTOM_SECTION_ID);
            push_leb128(stripped, name.len() + kept_len);
            stripped.extend_from_slice(name);
            for subsection in kept_subsections(subsections) {
                stripped.extend_from_slice(subsection);
            }
        } else if let Some(stripped) = &mut stripped {
            stripped.extend_from_slice(&rest[..rest.len() - after.len()]);
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
    let (&id, mut after) = bytes.split_first()?;
    let size = read_var_u32(&mut after)?;
    let payload = read_bytes(&mut after, size)?;
    if id != CUSTOM_SECTION_ID {
        return Some((Section::Other, after));
    }
    let mut subsections = payload;
    let name_len = read_var_u32(&mut subsections)?;
    if read_bytes(&mut subsections, name_len)? != NAME_SECTION_NAME {
        return Some((Section::Other, after));
    }
    let name = &payload[..payload.len() - subsections.len()];
    Some((Section::Name { name, subsections }, after))
}

/// Iterates over the kept subsections of a `name` section, as their bytes (id,
/// size and content). If a subsection cannot be parsed, the last item is the
/// bytes from that subsection to the end of the section.
fn kept_subsections(mut subsections: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut last_kept_id = None;
    std::iter::from_fn(move || {
        while !subsections.is_empty() {
            let Some((id, content, after)) = split_subsection(subsections) else {
                return Some(std::mem::take(&mut subsections));
            };
            let Some(indices_in_order) = parse_content(id, content) else {
                return Some(std::mem::take(&mut subsections));
            };
            let subsection = &subsections[..subsections.len() - after.len()];
            subsections = after;
            if indices_in_order
                && last_kept_id.is_none_or(|last_kept_id| id > last_kept_id)
                && !PARAMETER_NAMES_SUBSECTION_IDS.contains(&id)
            {
                last_kept_id = Some(id);
                return Some(subsection);
            }
        }
        None
    })
}

/// Splits the subsection at the start of `bytes` into its id and its content,
/// and the bytes after it. Like wasmparser, only accepts ids that fit in 7
/// bits.
fn split_subsection(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&id, mut after) = bytes.split_first()?;
    if id & 0x80 != 0 {
        return None;
    }
    let size = read_var_u32(&mut after)?;
    let content = read_bytes(&mut after, size)?;
    Some((id, content, after))
}

/// Parses the content of the subsection with the given id like wasmparser
/// does: the module name (0), a name map (1, 4 to 9 and 11) or an indirect
/// name map (2, 3 and 10). Returns whether the indices of its name maps are
/// strictly increasing, or `None` if it cannot be parsed. The content of the
/// other subsections is not parsed.
fn parse_content(id: u8, mut content: &[u8]) -> Option<bool> {
    let indices_in_order = match id {
        0 => read_name(&mut content, Some(MAX_NAME_LEN)).map(|()| true),
        1 | 4..=9 | 11 => read_name_map(&mut content, None),
        2 | 3 | 10 => read_indirect_name_map(&mut content),
        _ => return Some(true),
    }?;
    content.is_empty().then_some(indices_in_order)
}

/// Reads a name map whose names are at most `max_name_len` bytes long, and
/// returns whether its indices are strictly increasing.
fn read_name_map(bytes: &mut &[u8], max_name_len: Option<usize>) -> Option<bool> {
    read_map(bytes, |bytes| read_name(bytes, max_name_len).map(|()| true))
}

/// Reads an indirect name map, and returns whether its indices and the indices
/// of each of its inner name maps are strictly increasing.
fn read_indirect_name_map(bytes: &mut &[u8]) -> Option<bool> {
    read_map(bytes, |bytes| read_name_map(bytes, Some(MAX_NAME_LEN)))
}

/// Reads a count followed by that many entries, each an index followed by what
/// `read_value` reads. Returns whether the indices are strictly increasing and
/// `read_value` returned `true` for each entry.
fn read_map(
    bytes: &mut &[u8],
    mut read_value: impl FnMut(&mut &[u8]) -> Option<bool>,
) -> Option<bool> {
    let count = read_var_u32(bytes)?;
    let mut last_index = None;
    let mut in_order = true;
    for _ in 0..count {
        let index = read_var_u32(bytes)?;
        in_order &= read_value(bytes)? && last_index.is_none_or(|last_index| index > last_index);
        last_index = Some(index);
    }
    Some(in_order)
}

/// Reads a name: its length and its bytes, which have to be UTF-8 and, if
/// `max_len` is given, at most that long.
fn read_name(bytes: &mut &[u8], max_len: Option<usize>) -> Option<()> {
    let len = read_var_u32(bytes)?;
    if max_len.is_some_and(|max_len| len > max_len) {
        return None;
    }
    let name = read_bytes(bytes, len)?;
    std::str::from_utf8(name).is_ok().then_some(())
}

/// Reads an unsigned LEB128 `u32` like wasmparser does: at most 5 bytes, of
/// which the 5th may only use its low 4 bits.
fn read_var_u32(bytes: &mut &[u8]) -> Option<usize> {
    let mut value = 0_usize;
    for (i, &byte) in bytes.iter().take(5).enumerate() {
        if i == 4 && byte >> 4 != 0 {
            return None;
        }
        value |= usize::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            *bytes = &bytes[i + 1..];
            return Some(value);
        }
    }
    None
}

fn read_bytes<'a>(bytes: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (read, after) = bytes.split_at_checked(len)?;
    *bytes = after;
    Some(read)
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

    /// Encodes a name: its length and its bytes.
    fn name(bytes: &[u8]) -> Vec<u8> {
        let mut name = vec![];
        push_leb128(&mut name, bytes.len());
        name.extend_from_slice(bytes);
        name
    }

    /// Encodes a name map with the given indices and names.
    fn name_map(names: &[(usize, &[u8])]) -> Vec<u8> {
        let mut map = vec![];
        push_leb128(&mut map, names.len());
        for (index, bytes) in names {
            push_leb128(&mut map, *index);
            map.extend(name(bytes));
        }
        map
    }

    /// Encodes an indirect name map with the given indices and encoded name
    /// maps.
    fn indirect_name_map(maps: &[(usize, Vec<u8>)]) -> Vec<u8> {
        let mut map = vec![];
        push_leb128(&mut map, maps.len());
        for (index, name_map) in maps {
            push_leb128(&mut map, *index);
            map.extend_from_slice(name_map);
        }
        map
    }

    /// The encoded name of a `name` section.
    fn encoded_name() -> Vec<u8> {
        name(NAME_SECTION_NAME)
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

    /// Subsection 0, naming the module.
    fn module_name() -> Vec<u8> {
        section(0, &[1, b'm'])
    }

    /// Subsection 1, naming function 0.
    fn function_names() -> Vec<u8> {
        section(1, &[1, 0, 1, b'f'])
    }

    /// Subsection 2, naming local 0 of function 0.
    fn local_names() -> Vec<u8> {
        section(2, &[1, 0, 1, 0, 1, b'x'])
    }

    /// Subsection 12 or 13, naming parameter 0 of type 0.
    fn parameter_names(id: u8) -> Vec<u8> {
        section(id, &[1, 0, 1, 0, 1, b'p'])
    }

    fn assert_unchanged(wasm: &[u8]) {
        let result = remove_ignored_name_subsections(wasm);
        assert!(
            matches!(result, Cow::Borrowed(bytes) if std::ptr::eq(bytes, wasm)),
            "expected the input itself, got {result:?}"
        );
    }

    fn assert_stripped(wasm: &[u8], expected: &[u8]) {
        let result = remove_ignored_name_subsections(wasm);
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
    fn well_formed_name_section_is_unchanged() {
        let [types, functions, code] = type_function_code_sections();
        let unknown = section(14, &[1, 2, 3]);
        assert_unchanged(&module(&[
            types,
            functions,
            code,
            name_section(&[module_name(), function_names(), local_names(), unknown]),
        ]));
        assert_unchanged(&module(&[name_section(&[])]));

        // Every known subsection up to 11, with gaps between indices, the
        // largest index, empty names and empty maps. Each inner map has its
        // own order, so it can start at 0 again.
        let names = name_map(&[(0, b"a"), (1, b""), (7, b"c"), (0xffff_ffff, b"d")]);
        let indirect_names = indirect_name_map(&[
            (0, names.clone()),
            (1, name_map(&[])),
            (5, name_map(&[(0, b"e")])),
        ]);
        let mut subsections = vec![module_name()];
        for id in 1..=11 {
            if [2, 3, 10].contains(&id) {
                subsections.push(section(id, &indirect_names));
            } else {
                subsections.push(section(id, &names));
            }
        }
        subsections.extend([section(14, &[]), section(0x7f, &[1, 2, 3])]);
        assert_unchanged(&module(&[name_section(&subsections)]));
    }

    #[test]
    fn parameter_names_are_removed() {
        let [types, functions, code] = type_function_code_sections();
        let expected = module(&[
            types.clone(),
            functions.clone(),
            code.clone(),
            name_section(&[module_name(), function_names(), local_names()]),
        ]);
        for ids in [vec![12], vec![13], vec![12, 13], vec![13, 12, 12]] {
            let mut subsections = vec![module_name(), function_names()];
            subsections.extend(ids.into_iter().map(parameter_names));
            subsections.push(local_names());
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
        // a name map that declares more names than it holds, and an indirect
        // name map whose indices are out of order.
        for payload in [&[1, 0, 1, 0, 1, 0xff][..], &[1, 0, 9], &[2, 1, 0, 0, 0]] {
            assert_stripped(
                &module(&[name_section(&[function_names(), section(12, payload)])]),
                &module(&[name_section(&[function_names()])]),
            );
        }
    }

    #[test]
    fn subsections_out_of_order_are_removed() {
        let other_module_name = section(0, &[1, b'n']);
        let unknown = |id| section(id, &[1, 2, 3]);
        for (subsections, kept) in [
            // A repeated id, and a smaller id after a greater one.
            (
                vec![function_names(), function_names()],
                vec![function_names()],
            ),
            (vec![local_names(), function_names()], vec![local_names()]),
            (
                vec![module_name(), other_module_name.clone()],
                vec![module_name()],
            ),
            (
                vec![function_names(), module_name()],
                vec![function_names()],
            ),
            (
                vec![unknown(15), unknown(14), unknown(15)],
                vec![unknown(15)],
            ),
            // Each id is compared with the id of the last kept subsection, not
            // with that of a removed one.
            (
                vec![local_names(), function_names(), unknown(14)],
                vec![local_names(), unknown(14)],
            ),
            (
                vec![
                    parameter_names(13),
                    function_names(),
                    parameter_names(12),
                    local_names(),
                ],
                vec![function_names(), local_names()],
            ),
            (
                vec![
                    section(1, &name_map(&[(1, b"b"), (0, b"a")])),
                    function_names(),
                ],
                vec![function_names()],
            ),
        ] {
            assert_stripped(
                &module(&[name_section(&subsections)]),
                &module(&[name_section(&kept)]),
            );
        }
    }

    #[test]
    fn name_maps_out_of_order_are_removed() {
        let expected = module(&[name_section(&[module_name()])]);
        // Decreasing, repeated, and decreasing after a gap.
        let names_out_of_order = [
            name_map(&[(1, b"b"), (0, b"a")]),
            name_map(&[(0, b"a"), (0, b"b")]),
            name_map(&[(0, b"a"), (2, b"c"), (1, b"b")]),
        ];
        for id in [1, 4, 5, 6, 7, 8, 9, 11] {
            for names in &names_out_of_order {
                assert_stripped(
                    &module(&[name_section(&[module_name(), section(id, names)])]),
                    &expected,
                );
            }
        }
        let names = name_map(&[(0, b"a"), (1, b"b")]);
        for id in [2, 3, 10] {
            for indirect_names in [
                // The outer map.
                indirect_name_map(&[(1, names.clone()), (0, names.clone())]),
                indirect_name_map(&[(0, names.clone()), (0, names.clone())]),
                // An inner map.
                indirect_name_map(&[(0, names_out_of_order[0].clone())]),
                indirect_name_map(&[(0, names.clone()), (1, names_out_of_order[1].clone())]),
            ] {
                assert_stripped(
                    &module(&[name_section(&[module_name(), section(id, &indirect_names)])]),
                    &expected,
                );
            }
        }
    }

    #[test]
    fn indices_are_compared_by_value() {
        // Index 1 in the longest encoding before index 0, and index 0 in the
        // longest encoding before index 1.
        let padded = |index: u8| [0x80 | index, 0x80, 0x80, 0x80, 0];
        let out_of_order = section(1, &[&[2][..], &padded(1), &[1, b'a', 0, 1, b'b']].concat());
        let in_order = section(1, &[&[2][..], &padded(0), &[1, b'a', 1, 1, b'b']].concat());
        assert_stripped(
            &module(&[name_section(&[module_name(), out_of_order])]),
            &module(&[name_section(&[module_name()])]),
        );
        assert_unchanged(&module(&[name_section(&[module_name(), in_order])]));
    }

    #[test]
    fn names_are_limited_in_length_as_in_wasmparser() {
        let longest = [b'x'; MAX_NAME_LEN];
        let too_long = [b'x'; MAX_NAME_LEN + 1];
        // A module name or a name in an inner map of 100_000 bytes, and a
        // longer name in a name map, can be parsed, so the parameter names
        // after them are removed.
        for parsed in [
            section(0, &name(&longest)),
            section(2, &indirect_name_map(&[(0, name_map(&[(0, &longest)]))])),
            section(4, &name_map(&[(0, &too_long)])),
        ] {
            assert_stripped(
                &module(&[name_section(&[parsed.clone(), parameter_names(12)])]),
                &module(&[name_section(&[parsed])]),
            );
        }
        // A longer module name or name in an inner map cannot be parsed, so
        // the rest of the section is kept.
        for unparsed in [
            section(0, &name(&too_long)),
            section(2, &indirect_name_map(&[(0, name_map(&[(0, &too_long)]))])),
        ] {
            assert_unchanged(&module(&[name_section(&[unparsed, parameter_names(12)])]));
        }
    }

    #[test]
    fn unparsable_subsections_are_kept_with_the_rest_of_the_section() {
        // Each subsection would be removed if it could be parsed: its id is
        // not greater than that of the function names before it, or one of its
        // name maps is out of order.
        for unparsable in [
            // A module name that is not UTF-8, that is cut off, without a
            // length, or followed by more bytes.
            section(0, &[1, 0xff]),
            section(0, &[2, b'm']),
            section(0, &[]),
            section(0, &[1, b'm', 0]),
            // Function names without a count, or out of order with a name
            // that is not UTF-8.
            section(1, &[]),
            section(1, &name_map(&[(1, b"b"), (0, b"\xff")])),
            // Type names out of order that declare more names than they hold,
            // with bytes after their names, or with an index whose encoding is
            // too long.
            section(4, &[3, 1, 1, b'b', 0, 1, b'a']),
            section(4, &[&name_map(&[(1, b"b"), (0, b"a")])[..], &[0]].concat()),
            section(
                4,
                &[2, 1, 1, b'b', 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, b'a'],
            ),
            // Local names out of order with an inner name that is not UTF-8,
            // and field names out of order with an inner map that declares
            // more names than it holds.
            section(
                2,
                &indirect_name_map(&[(1, name_map(&[])), (0, name_map(&[(0, b"\xff")]))]),
            ),
            section(10, &[2, 1, 0, 0, 2, 0, 1, b'a']),
        ] {
            let kept = module(&[name_section(&[
                function_names(),
                unparsable.clone(),
                parameter_names(12),
            ])]);
            assert_unchanged(&kept);
            assert_stripped(
                &module(&[name_section(&[
                    function_names(),
                    parameter_names(13),
                    unparsable,
                    parameter_names(12),
                ])]),
                &kept,
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
        // encoding is cut off by the end of the section or is too long, or
        // whose id does not fit in 7 bits.
        for tail in [
            [&[1, 0x7f, 0][..], &parameter_names(13)].concat(),
            vec![1, 0x80],
            [&too_long_size[..], &parameter_names(13)].concat(),
            [&[0x80 | 12][..], &parameter_names(12)[1..]].concat(),
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
                name_section(&[function_names(), function_names()]),
            ]),
            &module(&[
                types,
                functions,
                code,
                stripped.clone(),
                stripped.clone(),
                stripped.clone(),
                stripped,
            ]),
        );
        // The order of the ids is checked in each section on its own.
        assert_unchanged(&module(&[
            name_section(&[module_name(), local_names()]),
            name_section(&[module_name(), function_names()]),
        ]));
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
