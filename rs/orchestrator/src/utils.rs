use crate::error::OrchestratorError;
use ic_logger::{info, ReplicaLogger};
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Re-execute the current process, exactly as it was originally called.
pub(crate) fn reexec_current_process(logger: &ReplicaLogger) -> OrchestratorError {
    let args: Vec<String> = env::args().collect();
    info!(
        logger,
        "Restarting the current process with the same arguments it was originally executed with: {:?}",
        &args[..]
    );
    let error = exec::Command::new(&args[0]).args(&args[1..]).exec();
    OrchestratorError::ExecError(PathBuf::new(), error)
}

/// Delete old files/directories in the given dir, keeping the
/// `num_entries_to_keep` youngest entries and not deleting any file/dir younger
/// than `min_age`
pub(crate) fn gc_dir(
    logger: &ReplicaLogger,
    dir: &Path,
    num_entries_to_keep: usize,
    min_age: Duration,
) -> io::Result<()> {
    let mut dir_size = fs::read_dir(dir)?.count();

    while dir_size > num_entries_to_keep {
        if let Some(oldest_entry) = get_oldest_entry(dir) {
            let metadata = fs::metadata(&oldest_entry)?;
            let entry_age = metadata
                .created()?
                .elapsed()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if entry_age < min_age {
                break;
            } else {
                info!(logger, "Deleting old path: {:?}", &oldest_entry);
                if oldest_entry.is_file() {
                    fs::remove_file(&oldest_entry)?;
                } else if oldest_entry.is_dir() {
                    fs::remove_dir_all(&oldest_entry)?;
                }
                dir_size -= 1;
            }
        } else {
            break;
        }
    }

    Ok(())
}

/// Return the oldest created file or directory in `dir`
pub(crate) fn get_oldest_entry(dir: &Path) -> Option<PathBuf> {
    let mut oldest: Option<(SystemTime, PathBuf)> = None;

    for entry in fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let metadata = entry.metadata().ok()?;
        let created = metadata.created().ok()?;

        if let Some((oldest_found, _)) = &oldest {
            if created < *oldest_found {
                oldest = Some((created, entry.path()));
            }
        } else {
            oldest = Some((created, entry.path()));
        }
    }

    oldest.map(|pair| pair.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::replica_logger::no_op_logger;
    use std::fs::File;
    use std::thread;
    use std::time::Duration;

    #[test]
    #[ignore] // OPS-177
    fn test_get_oldest_entry() {
        let tmpdir = tempfile::Builder::new()
            .prefix("test_get_oldest_entry")
            .tempdir()
            .unwrap();

        assert!(get_oldest_entry(&tmpdir.path().to_path_buf()).is_none());

        let path = tmpdir.path();

        File::create(path.join("file1")).unwrap();
        thread::sleep(Duration::from_millis(5));
        File::create(path.join("file2")).unwrap();
        thread::sleep(Duration::from_millis(5));
        File::create(path.join("file3")).unwrap();

        let oldest_path = get_oldest_entry(&tmpdir.path().to_path_buf())
            .unwrap()
            .into_boxed_path();
        let oldest_file_name = oldest_path.file_name().unwrap().to_str().unwrap();

        assert_eq!(oldest_file_name, "file1");
    }

    #[test]
    #[ignore] // OPS-177
    fn test_gc_dir() {
        let tmpdir = tempfile::Builder::new()
            .prefix("test_gc_dir")
            .tempdir()
            .unwrap();

        let logger = no_op_logger();

        let tmpdir_path = tmpdir.path().to_path_buf();
        assert!(gc_dir(&logger, &tmpdir_path, 5, Duration::from_secs(0)).is_ok());

        let path = tmpdir.path();

        let path1 = path.join("dir1");
        fs::create_dir(&path1).unwrap();
        File::create(path1.join("file1")).unwrap();
        thread::sleep(Duration::from_millis(5));

        let path2 = path.join("file2");
        File::create(&path2).unwrap();
        thread::sleep(Duration::from_millis(5));

        let path3 = path.join("file3");
        File::create(&path3).unwrap();

        // Assert that no files are deleted if dir size is 3 and we pass in
        // max_file_count=5
        gc_dir(&logger, &tmpdir_path, 5, Duration::from_secs(0)).unwrap();
        assert_eq!(fs::read_dir(&tmpdir_path).unwrap().count(), 3);

        // Assert that no files are deleted if min_age=100s
        gc_dir(&logger, &tmpdir_path, 0, Duration::from_secs(100)).unwrap();
        assert_eq!(fs::read_dir(&tmpdir_path).unwrap().count(), 3);

        // Assert that file1 and file2 are deleted and file3 is untouched
        gc_dir(&logger, &tmpdir_path, 1, Duration::from_secs(0)).unwrap();
        assert!(!path1.exists());
        assert!(!path2.exists());
        assert!(path3.exists());
    }
}
