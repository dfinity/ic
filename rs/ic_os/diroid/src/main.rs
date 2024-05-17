use std::env;
use std::os::unix::fs::MetadataExt;

use walkdir::WalkDir;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        panic!("Incorrect arguments!");
    }

    for entry in WalkDir::new(&args[1]) {
        let entry = entry.unwrap();

        let metadata = entry.metadata().unwrap();
        println!(
            "{} {} {} {:o}",
            entry.path().strip_prefix(&args[1]).unwrap().display(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode()
        );
    }
}
