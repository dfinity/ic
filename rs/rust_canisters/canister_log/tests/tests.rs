use ic_canister_log::{declare_log_buffer, export, log};

mod buf_mod {
    use ic_canister_log::declare_log_buffer;

    declare_log_buffer!(name = LOG, capacity = 100);
}

#[test]
fn test_other_module_buffer() {
    log!(buf_mod::LOG, "test message no args");
    log!(buf_mod::LOG, "test message: {}", 1);
    log!(buf_mod::LOG, "test message: {}, {}", "foo", 2);

    let entries = export(&buf_mod::LOG);

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].message, "test message no args");
    assert_eq!(entries[1].message, "test message: 1");
    assert_eq!(entries[2].message, "test message: foo, 2");

    assert!(
        entries[0].file.ends_with("tests.rs"),
        "entry should record the file name {:?}",
        entries[0]
    );
}

declare_log_buffer!(name = ERROR, capacity = 100);
declare_log_buffer!(name = INFO, capacity = 100);

#[test]
fn test_two_buffers() {
    log!(ERROR, "error: too much sugar");
    log!(INFO, "info: everything is OK");

    let errors = export(&ERROR);
    let infos = export(&INFO);

    assert_eq!(errors.len(), 1);
    assert_eq!(infos.len(), 1);
}

declare_log_buffer!(name = SMALL, capacity = 2);

#[test]
fn test_log_rotation() {
    log!(SMALL, "entry {}", 1);
    log!(SMALL, "entry {}", 2);

    let entries = export(&SMALL);

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].message, "entry 1");
    assert_eq!(entries[1].message, "entry 2");

    log!(SMALL, "entry {}", 3);

    let entries = export(&SMALL);

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].message, "entry 2");
    assert_eq!(entries[1].message, "entry 3");
}
