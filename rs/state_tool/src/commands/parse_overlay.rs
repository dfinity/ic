use ic_replicated_state::page_map::storage::OverlayFile;
use std::cmp::Reverse;
use std::path::PathBuf;

pub fn do_parse_overlay(path: PathBuf) -> Result<(), String> {
    let overlay = OverlayFile::load(&path).map_err(|_| "Unable to open file")?;

    let mut ranges: Vec<_> = overlay.index_iter().collect();

    for range in &ranges {
        println!(
            "Range ({},{}) starting at {}",
            range.start_page, range.end_page, range.start_file_index
        );
    }

    println!("{} pages in {} ranges", overlay.num_pages(), ranges.len(),);

    ranges.sort_by_key(|range| Reverse(range.end_page.get() - range.start_page.get()));

    println!("Longest ranges:");
    for range in ranges.iter().take(5) {
        println!(
            "Range ({},{}) with length {}",
            range.start_page,
            range.end_page,
            range.end_page.get() - range.start_page.get(),
        );
    }

    Ok(())
}
