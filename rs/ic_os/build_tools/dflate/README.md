# dflate

Create deterministic tar archives quickly.


GNU tar has two methods of hole detection for sparse files, `raw` and `seek`.
`raw` is slow because it scans the entire file, and `seek` is not deterministic
because the hole detection is based on the block size of the underlying
filesystem. This tool combines the two using `SEEK_DATA`/`SEEK_HOLE` to strip
large holes, and a fixed-size-block scan to strip the rest.


The result is a GNU tar archive with sparse format equivalent to `--hole-detection=raw`.
