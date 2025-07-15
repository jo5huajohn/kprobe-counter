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
	local it=0
		cat > "src/$FILE_HDR.bpf.c" <<EOF
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
EOF

	while IFS= read -r line; do
		modified=${line^^}
		cat >> "src/$FILE_HDR.bpf.c" <<EOF

SEC("kprobe/$line")
int BPF_KPROBE_$it(struct pt_regs *ctx) { 
	return increment_counter(${modified//./__});
}
EOF
	((it++))
	done <<< "$(cat "$FILE_KSYMS")"
}

if [[ -z $FILE_HDR || -z $FILE_KSYMS ]]; then
	echo "Provide kernel symbols file"
	exit 1
fi

generate_header
generate_bpf_program
