use crate::dashboard::{DashboardBlob, DashboardTemplate};
use askama::Template;
use scraper::{Html, Selector};

#[test]
fn should_render_empty_dashboard() {
    let dashboard = DashboardTemplate {
        total_blobs: 0,
        total_size_bytes: 0,
        blobs: vec![],
    };
    let html = dashboard.render().unwrap();
    let parsed = Html::parse_document(&html);

    assert_has_text(&parsed, "#total-blobs > td > code", "0");
    assert_has_text(&parsed, "#total-size > td > code", "0");
    assert!(
        parsed
            .select(&Selector::parse("#blobs + table > tbody > tr").unwrap())
            .next()
            .is_none(),
        "expected no blob rows"
    );
}

#[test]
fn should_render_blobs() {
    let dashboard = DashboardTemplate {
        total_blobs: 2,
        total_size_bytes: 300,
        blobs: vec![
            DashboardBlob {
                hash: "98ac5cfe873a7b42b7c98a1b3fbeff2255e340deb9c80aa9eb0bd0ba3a0d2a99"
                    .to_string(),
                uploader: "principal-1".to_string(),
                size: 100,
                inserted_at_ns: 1_700_000_000_000_000_000,
                tags: vec!["ledger".to_string(), "u256".to_string()],
            },
            DashboardBlob {
                hash: "3d33f9edeae50572a42378d1eaaa29f5149543ec16268797b058156b1b575a04"
                    .to_string(),
                uploader: "principal-2".to_string(),
                size: 200,
                inserted_at_ns: 1_700_000_001_000_000_000,
                tags: vec![],
            },
        ],
    };
    let html = dashboard.render().unwrap();
    let parsed = Html::parse_document(&html);

    assert_has_text(&parsed, "#total-blobs > td > code", "2");
    assert_has_text(&parsed, "#total-size > td > code", "300");

    assert_row_contains(
        &parsed,
        1,
        "98ac5cfe873a7b42b7c98a1b3fbeff2255e340deb9c80aa9eb0bd0ba3a0d2a99",
        "principal-1",
        "100",
        "ledger, u256",
    );
    assert_row_contains(
        &parsed,
        2,
        "3d33f9edeae50572a42378d1eaaa29f5149543ec16268797b058156b1b575a04",
        "principal-2",
        "200",
        "",
    );
}

fn assert_has_text(html: &Html, selector: &str, expected: &str) {
    let sel = Selector::parse(selector).unwrap();
    let element = html
        .select(&sel)
        .next()
        .unwrap_or_else(|| panic!("selector '{selector}' not found"));
    let text: String = element.text().collect();
    assert_eq!(text, expected, "selector '{selector}'");
}

fn assert_row_contains(
    html: &Html,
    row: usize,
    hash: &str,
    uploader: &str,
    size: &str,
    tags: &str,
) {
    let row_sel =
        Selector::parse(&format!("#blobs + table > tbody > tr:nth-child({row})")).unwrap();
    let row_el = html
        .select(&row_sel)
        .next()
        .unwrap_or_else(|| panic!("row {row} not found"));
    let cells: Vec<String> = row_el
        .select(&Selector::parse("td").unwrap())
        .map(|td| td.text().collect::<String>())
        .collect();
    assert_eq!(cells[0], hash, "hash mismatch in row {row}");
    assert_eq!(cells[1], uploader, "uploader mismatch in row {row}");
    assert_eq!(cells[2], size, "size mismatch in row {row}");
    // cells[3] is the formatted timestamp, just check it's not empty
    assert!(!cells[3].is_empty(), "timestamp missing in row {row}");
    assert_eq!(cells[4], tags, "tags mismatch in row {row}");
}
