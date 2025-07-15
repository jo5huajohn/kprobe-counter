#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <csignal>
#include <cstdint>

#include "tracer.skel.h"
#include "tracer.h"

static volatile sig_atomic_t g_terminate = false;

static void signal_handler(int sig) {
	g_terminate = true;
}

int main() {
	int ret = 0;
	uint64_t value = 0;

	std::signal(SIGINT, signal_handler);

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);

	struct tracer_bpf *skel = tracer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open eBPF skeleton\n");
		return 1;
	}

	ret = tracer_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load eBPF skeleton\n");
		tracer_bpf__destroy(skel);
		return 1;
	}

	ret = tracer_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach eBPF programs\n");
		tracer_bpf__destroy(skel);
		return 1;
	}

	while (!g_terminate) {
		sleep(1);
	}

	for (unsigned int fn = 0; fn < NUM_KSYMS; fn++) {
		ret = bpf_map__lookup_elem(skel->maps.syscall_count, &fn, sizeof(uint32_t), &value, sizeof(uint64_t), 0);
		if (!ret) {
			printf("%s: %lu\n", ksyms_enum_to_string(static_cast<enum ksyms>(fn)), value);
		}
	}

	tracer_bpf__destroy(skel);

	return 0;
}
