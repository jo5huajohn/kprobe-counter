# Counter

Count the number of times a kernel symbol is invoked.

This program counts the number of times a kernel symbol was invoked during the lifetime of the program using eBPF kernel probes. A script generates a corresponding number to be used as a key for the kernel symbol. This key is then used in a hash map, with the corresponding value of the key being updated every time the symbol is invoked. Once the program is killed using Ctrl+C, the program prints a report.


## Prerequisites

- bpftool
- clang
- libbpf-dev
- make
- A file containing all the kernel symbols to be monitored is also required, one symbol per line. Example:
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

If running inside toolbx containers, this [Containerfile](https://github.com/jo5huajohn/Containerfiles-toolbx/tree/main/fedora-42-bpf) can be used to build a container containing all the dependencies required to build this and other eBPF projects.

## Build

- `scripts/generate_bpf_programs.sh <name of file containing symbols>`
- `make`

## Run

- `sudo src/counter <path to block device>`

## Generated Report

![image](resources/report.png)
