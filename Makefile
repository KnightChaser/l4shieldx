CLANG ?= clang
BPF_OBJ = bpf/xdp_prog.o

all: $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ)

$(BPF_OBJ): bpf/xdp_prog.c
	$(CLANG) -O2 -Wall -target bpf -g \
		-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/') \
		-Ibpf -c $< -o $@

