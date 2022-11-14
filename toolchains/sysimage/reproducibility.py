import atexit
import os
import shutil
import subprocess
import tempfile


def get_tmpdir_checking_block_size(dirpath="/var/sysimage", expected_block_size=4096):
    if not os.path.isdir(dirpath):
        dirpath = None

    tmpdir = tempfile.mkdtemp(dir=dirpath)
    atexit.register(lambda: shutil.rmtree(tmpdir))
    print(f"get_tmpdir_checking_block_size: {tmpdir}")

    # The block size of the filesystem underlying the specified directory is
    # discovered by writing a single byte to a file and then truncating that
    # file to 1M in size. An entire block will be allocated to store the byte,
    # but the remainder of the 1M will be represented sparsely as a file hole.
    # By seeking to the start of this hole the size of the block can be found.
    tmpfile_path = os.path.join(tmpdir, ".block-size-check")
    tmpfile = os.open(tmpfile_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.write(tmpfile, b"x")
    os.ftruncate(tmpfile, 1024 * 1024)
    block_size = os.lseek(tmpfile, 0, os.SEEK_HOLE)
    os.close(tmpfile)

    # It is important that block size is consistent across all build environments
    # to ensure disk images are reproducible. The issue manifests because tar has
    # special handling to efficiently store sparse files (it uses lseek to create
    # a map of all the file holes). So a change in block size alters this map,
    # and hence the tar archive produced.
    if block_size != expected_block_size:
        raise RuntimeError(f"{tmpdir} has block size {block_size} (expected {expected_block_size})")

    return tmpdir


def print_artifact_info(path):
    subprocess.run(
        [
            "bash",
            "-c",
            f"""
                echo 'info for artifact: {path}:'
                sha256sum {path}
                stat {path}
            """,
        ]
    )
