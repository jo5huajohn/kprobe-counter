#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <csignal>
#include <cstdint>
#include <iostream>

#include "iofilter.h"
#include "tracer.skel.h"
#include "tracer.h"

static volatile sig_atomic_t g_terminate = false;

static void signal_handler(int sig) {
	g_terminate = true;
}

int main(int argc, char *argv[]) {
	int ret = 0;
	uint64_t value = 0;
	struct stat sb;

	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <block device>" << std::endl;
		return 1;
	}

	std::signal(SIGINT, signal_handler);

	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
	setrlimit(RLIMIT_MEMLOCK, &r);

	ret = lstat(argv[1], &sb);
	if (ret) {
		std::cerr << "stat: " << strerror(errno);
		return 1;
	}

	struct tracer_bpf *skel = tracer_bpf__open();
	if (!skel) {
		std::cerr << "Failed to open eBPF skeleton" << std::endl;
		return 1;
	}

	ret = tracer_bpf__load(skel);
	if (ret) {
		std::cerr << "Failed to load eBPF skeleton" << std::endl;
		tracer_bpf__destroy(skel);
		return 1;
	}

	if (S_ISBLK(sb.st_mode)) {
		struct iofilter_dev iodev;
		iodev.major = major(sb.st_rdev);
		iodev.minor = minor(sb.st_rdev);

		int key = 0;
		bpf_map__update_elem(skel->maps.iofilter, &key, sizeof(int), &iodev, sizeof(struct iofilter_dev), BPF_NOEXIST);
	} else {
		std::cerr << argv[1] << " is not a block device" << std::endl;
		tracer_bpf__destroy(skel);
		return 1;
	}

	ret = tracer_bpf__attach(skel);
	if (ret) {
		std::cerr << "Failed to attach eBPF programs" << std::endl;
		tracer_bpf__destroy(skel);
		return 1;
	}

	while (!g_terminate) {
		sleep(1);
	}

	std::cout << std::endl;
	for (unsigned int fn = 0; fn < NUM_KSYMS; fn++) {
		ret = bpf_map__lookup_elem(skel->maps.syscall_count, &fn, sizeof(uint32_t), &value, sizeof(uint64_t), 0);
		if (!ret) {
			std::cout << ksyms_enum_to_string(static_cast<enum ksyms>(fn)) << ": " << value << std::endl;
		}
	}

	tracer_bpf__destroy(skel);

	return 0;
}
