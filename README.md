# Counter

Count the number of times a kernel symbol is invoked.

This program counts the number of times a kernel symbol was invoked during the lifetime of the program using eBPF kernel probes. A script generates a corresponding number to be used as a key for the kernel symbol. This key is then used in a hash map, with the corresponding value of the key being updated every time the symbol is invoked. Once the program is killed using Ctrl+C, the program prints a report.

## Build

**Prerequisites:** clang, libbpf, and make are required to run this program. A file containing all the kernel symbols to be monitored is also required, one symbol per line.
Example:
```
btrfs_lookup
btrfs_getattr
btrfs_setattr
btrfs_file_read_iter
btrfs_file_write_iter
btrfs_sync_file
btrfs_create
btrfs_unlink
btrfs_mkdir
btrfs_rename
```

- `scripts/generate_bpf_programs.sh <name of file containing symbols>`
- `make`

## Run

- `sudo src/counter`
