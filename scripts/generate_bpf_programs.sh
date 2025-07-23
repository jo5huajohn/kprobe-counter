#!/bin/bash

FILE_KSYMS="$1"
FILE_HDR="tracer"

generate_header() {
	cat > "src/$FILE_HDR.h" <<EOF
#ifndef ${FILE_HDR^^}_H_
#define ${FILE_HDR^^}_H_

enum ksyms {
EOF
	
	local it=0
	while IFS= read -r line; do
		modified=${line^^}
		echo "	${modified//./__} = $it," >> "src/${FILE_HDR}.h"
		((it++))
	done <<< "$(cat "$FILE_KSYMS")"
	
	cat >> "src/$FILE_HDR.h" <<EOF
	NUM_KSYMS
};

static inline const char *ksyms_enum_to_string(enum ksyms ksym) {
	static const char *strings[] = {
EOF
	
	while IFS= read -r line; do
		echo "		\"$line\", " >> "src/${FILE_HDR}.h"
	done <<< "$(cat "$FILE_KSYMS")"
	
	cat >> "src/$FILE_HDR.h" <<EOF
	};
	
	return strings[ksym];
}

#endif
EOF
}

generate_bpf_program() {
	cat > "src/$FILE_HDR.bpf.c" <<EOF
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "iofilter.h"
#include "tracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct { 
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, NUM_KSYMS);
} syscall_count SEC(".maps");

const volatile struct iofilter_dev g_iodev SEC(".rodata");

static u32 __always_inline get_major(dev_t dev) {
	return (dev >> 20) & 0xfff;
}

static u32 __always_inline get_minor(dev_t dev) {
	return dev & 0xfffff;
}

static int increment_counter(u32 key, struct pt_regs *ctx) {
	static const u64 init = 1;

	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	struct super_block *sb = BPF_CORE_READ(inode, i_sb);
	dev_t dev = BPF_CORE_READ(sb, s_dev);

	u32 major = get_major(dev);
	u32 minor = get_minor(dev);
	if ((g_iodev.major != major) || (g_iodev.minor != minor)) {
		return 0;
	}

	u64 *val = bpf_map_lookup_elem(&syscall_count, &key);
	if (val) { 
		__sync_fetch_and_add(val, 1);
	} else { 
		bpf_map_update_elem(&syscall_count, &key, &init, BPF_NOEXIST);
	}

	return 0;
}
EOF

	while IFS= read -r line; do
		modified=${line^^}
		cat >> "src/$FILE_HDR.bpf.c" <<EOF

SEC("kprobe/$line")
int kprobe_$line(struct pt_regs *ctx) {
	return increment_counter(${modified//./__}, ctx);
}
EOF
	done <<< "$(cat "$FILE_KSYMS")"
}

if [[ -z $FILE_HDR || -z $FILE_KSYMS ]]; then
	echo "Provide kernel symbols file"
	exit 1
fi

generate_header
generate_bpf_program
