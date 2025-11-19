use ic_replicated_state::page_map::storage::OverlayFile;
use std::cmp::Reverse;
use std::path::PathBuf;

pub fn do_parse_overlay(path: PathBuf) -> Result<(), String> {
    let overlay = OverlayFile::load(&path).map_err(|_| "Unable to open file")?;
    println!("{overlay:#?}");

    let mut ranges: Vec<_> = overlay.index_iter().collect();
    println!("{} pages in {} ranges", overlay.num_pages(), ranges.len(),);

    ranges.sort_by_key(|range| Reverse(range.len()));

    println!("Longest ranges:");
    for range in ranges.iter().take(5) {
        println!("{:?} with length {}", range, range.len(),);
    }

    Ok(())
}
