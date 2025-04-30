# --------------------------------------------------
#  Configurable variables
# --------------------------------------------------
CLANG        ?= clang
GO           ?= go
BPF_DIR      := xdpcollector/bpf
BPF_SRC      := $(BPF_DIR)/xdp_prog.c
BPF_OBJ      := $(BPF_DIR)/xdp_prog.o
BTF_HEADER   := $(BPF_DIR)/vmlinux.h
GO_BIN       ?= l4shieldx

# For x86‑64 kernels use __TARGET_ARCH_x86, arm64 => aarch64, etc.
ARCH_FLAG    := -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/')

# --------------------------------------------------
# Phony targets
# --------------------------------------------------
.PHONY: all build-go clean run

# Default target
all: $(BTF_HEADER) $(BPF_OBJ) build-go

# Generate vmlinux.h once per kernel (requires bpftool >= v5.10)
$(BTF_HEADER):
	@echo "[Task] Generating $@"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build the eBPF object
$(BPF_OBJ): $(BPF_SRC) $(BTF_HEADER)
	@echo "[Task] Building $@"
	$(CLANG) -O2 -g -Wall -target bpf \
		$(ARCH_FLAG) \
		-I$(BPF_DIR) \
		-c $< -o $@

# Build Go control‑plane binary
build-go:
	@echo "[Task] Building $(GO_BIN)"
	$(GO) build -o $(GO_BIN) .

# Convenience: sudo‑run the freshly built binary
run: all
	sudo ./$(GO_BIN) $(ARGS)

# Remove generated artefacts
clean:
	$(GO) clean
	rm -f $(GO_BIN)
	rm -f $(BPF_OBJ)
	rm -f $(BTF_HEADER)

