PROJECT := counter

BPFTOOL = bpftool
CC = clang
CXX = clang++

ARCH = $(shell uname -m | sed 's/x86_64/x86/' \
	   					| sed 's/aarch64/arm64/')

SRC_DIR := src
SCRIPT_DIR := scripts

BPF_PROG := $(SRC_DIR)/tracer.bpf.c
BPF_OBJ := $(SRC_DIR)/tracer.bpf.o
BPF_SKEL := $(SRC_DIR)/tracer.skel.h
VMLINUX := $(SRC_DIR)/vmlinux.h

BIN := $(SRC_DIR)/$(PROJECT)
SRC := $(SRC_DIR)/main.cpp

CFLAGS := -O2 -g -Wall -Werror
CLANG_BPF_FLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(ARCH) -I$(SRC_DIR)
LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean test

all: $(BIN)

$(VMLINUX):
	@echo "  GEN     $@"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_PROG) $(VMLINUX)
	@echo "  CLANG   $@"
	@$(CC) $(CLANG_BPF_FLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	@echo "  SKEL    $@"
	@$(BPFTOOL) gen skeleton $< > $@

$(BIN): $(SRC) $(BPF_SKEL)
	@echo "  CXX     $@"
	@$(CXX) $(CFLAGS) -I$(SRC_DIR) -o $@ $< $(LDFLAGS)

clean:
	@echo "  CLEAN"
	@$(RM) $(BPF_SKEL) $(VMLINUX) $(SRC_DIR)/*.o $(BPF_PROG) src/tracer.h $(BIN)
