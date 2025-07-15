#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "tracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct { 
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, NUM_KSYMS);
} syscall_count SEC(".maps");

int increment_counter(u32 key) { 
	static const u64 init = 1;

	u64 *val = bpf_map_lookup_elem(&syscall_count, &key);
	if (val) { 
		__sync_fetch_and_add(val, 1);
	} else { 
		bpf_map_update_elem(&syscall_count, &key, &init, BPF_NOEXIST);
	}

	return 0;
}

SEC("kprobe/btrfs_lookup")
int BPF_KPROBE_0(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_LOOKUP);
}

SEC("kprobe/btrfs_getattr")
int BPF_KPROBE_1(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_GETATTR);
}

SEC("kprobe/btrfs_setattr")
int BPF_KPROBE_2(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_SETATTR);
}

SEC("kprobe/btrfs_file_read_iter")
int BPF_KPROBE_3(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_FILE_READ_ITER);
}

SEC("kprobe/btrfs_file_write_iter")
int BPF_KPROBE_4(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_FILE_WRITE_ITER);
}

SEC("kprobe/btrfs_sync_file")
int BPF_KPROBE_5(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_SYNC_FILE);
}

SEC("kprobe/btrfs_create")
int BPF_KPROBE_6(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_CREATE);
}

SEC("kprobe/btrfs_unlink")
int BPF_KPROBE_7(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_UNLINK);
}

SEC("kprobe/btrfs_mkdir")
int BPF_KPROBE_8(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_MKDIR);
}

SEC("kprobe/btrfs_rename")
int BPF_KPROBE_9(struct pt_regs *ctx) { 
	return increment_counter(BTRFS_RENAME);
}
