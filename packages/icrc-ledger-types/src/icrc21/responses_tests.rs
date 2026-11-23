use super::*;
use serde_bytes::ByteBuf;

fn generic_display_memo(memo: &[u8]) -> String {
    let mut message = ConsentMessage::GenericDisplayMessage(String::new());
    message.add_memo(GenericMemo::Icrc1Memo(ByteBuf::from(memo.to_vec())));
    match message {
        ConsentMessage::GenericDisplayMessage(message) => message,
        ConsentMessage::FieldsDisplayMessage(_) => unreachable!(),
    }
}

fn fields_display_memo(memo: &[u8]) -> Vec<(String, Value)> {
    let mut message = ConsentMessage::FieldsDisplayMessage(FieldsDisplay {
        intent: String::new(),
        fields: vec![],
    });
    message.add_memo(GenericMemo::Icrc1Memo(ByteBuf::from(memo.to_vec())));
    match message {
        ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields,
        ConsentMessage::GenericDisplayMessage(_) => unreachable!(),
    }
}

fn memo_field(label: &str, content: &str) -> Vec<(String, Value)> {
    vec![(
        label.to_string(),
        Value::Text {
            content: content.to_string(),
        },
    )]
}

#[test]
fn should_show_printable_ascii_memo_as_text() {
    let memo = b"Invoice #42: [paid] *in full* <ok> \\ ~";
    assert_eq!(
        generic_display_memo(memo),
        "\n\n**Memo:**\n`Invoice #42: [paid] *in full* <ok> \\ ~`"
    );
    assert_eq!(
        fields_display_memo(memo),
        memo_field("Memo", "Invoice #42: [paid] *in full* <ok> \\ ~")
    );
}

#[test]
fn should_show_memo_that_could_alter_markdown_as_hex() {
    for memo in [
        &b"x`\n\n**Amount:**\n`0.0001 TOK"[..],
        b"x`[Verify now](https://example.com)`y",
        b"`",
        b"line\nbreak",
        b"carriage\rreturn",
        b"tab\tseparated",
        b"\x7f",
    ] {
        let message = generic_display_memo(memo);
        assert_eq!(
            message,
            format!("\n\n**Memo (hex):**\n`{}`", hex::encode(memo)),
            "memo: {memo:?}"
        );
        assert_eq!(message.matches('`').count(), 2, "memo: {memo:?}");
        assert_eq!(message.matches('\n').count(), 3, "memo: {memo:?}");
    }
}

#[test]
fn should_show_non_ascii_memo_as_hex_in_generic_display_only() {
    let memo = "Café ☕".as_bytes();
    assert_eq!(
        generic_display_memo(memo),
        format!("\n\n**Memo (hex):**\n`{}`", hex::encode(memo))
    );
    assert_eq!(fields_display_memo(memo), memo_field("Memo", "Café ☕"));
}

#[test]
fn should_show_memo_that_could_alter_fields_as_hex() {
    for memo in [
        "x\nAmount: 0.0001 TOK",
        "carriage\rreturn",
        "tab\tseparated",
        "nul\0",
        "del\u{7f}",
        "next line\u{85}",
        "line\u{2028}separator",
        "paragraph\u{2029}separator",
        "arabic letter mark\u{61C}",
        "left-to-right mark\u{200E}",
        "right-to-left mark\u{200F}",
        "embedding\u{202A}",
        "right-to-left override\u{202E}",
        "isolate\u{2066}",
        "pop directional isolate\u{2069}",
    ] {
        assert_eq!(
            fields_display_memo(memo.as_bytes()),
            memo_field("Memo (hex)", &hex::encode(memo)),
            "memo: {memo:?}"
        );
    }
}

#[test]
fn should_show_non_utf8_memo_as_hex() {
    let memo = [0xff, 0x00, 0x60];
    assert_eq!(generic_display_memo(&memo), "\n\n**Memo (hex):**\n`ff0060`");
    assert_eq!(
        fields_display_memo(&memo),
        memo_field("Memo (hex)", "ff0060")
    );
}

fn generic_display_expiration(utc_offset_minutes: i16) -> String {
    // 2026-07-28T12:00:00Z
    const EXPIRES_AT_NANOS: u64 = 1_785_240_000_000_000_000;
    let mut message = ConsentMessage::GenericDisplayMessage(String::new());
    message.add_expiration(Some(EXPIRES_AT_NANOS), Some(utc_offset_minutes));
    match message {
        ConsentMessage::GenericDisplayMessage(message) => message,
        ConsentMessage::FieldsDisplayMessage(_) => unreachable!(),
    }
}

#[test]
fn should_render_expiration_for_all_real_utc_offsets() {
    for (utc_offset_minutes, expected) in [
        (0, "Tue, 28 Jul 2026 12:00:00 +0000"),
        (60, "Tue, 28 Jul 2026 13:00:00 +0100"),
        (546, "Tue, 28 Jul 2026 21:06:00 +0906"),
        (547, "Tue, 28 Jul 2026 21:07:00 +0907"),
        (600, "Tue, 28 Jul 2026 22:00:00 +1000"),
        (780, "Wed, 29 Jul 2026 01:00:00 +1300"),
        (840, "Wed, 29 Jul 2026 02:00:00 +1400"),
        (-570, "Tue, 28 Jul 2026 02:30:00 -0930"),
        (-600, "Tue, 28 Jul 2026 02:00:00 -1000"),
        (-720, "Tue, 28 Jul 2026 00:00:00 -1200"),
    ] {
        assert_eq!(
            generic_display_expiration(utc_offset_minutes),
            format!("\n\n**Approval expiration:**\n{expected}"),
            "offset: {utc_offset_minutes}"
        );
    }
}

#[test]
fn should_reject_utc_offset_out_of_range_without_panicking() {
    for utc_offset_minutes in [26 * 60, -26 * 60, i16::MAX, i16::MIN] {
        assert_eq!(
            generic_display_expiration(utc_offset_minutes),
            format!(
                "\n\n**Approval expiration:**\nInvalid UTC offset: {utc_offset_minutes} minutes"
            ),
        );
    }
}
