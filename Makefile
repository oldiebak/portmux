.PHONY: all build bpf agent wrap clean

BUILD_DIR = build
AGENT_BIN = $(BUILD_DIR)/.pm
WRAP_BIN  = $(BUILD_DIR)/portmux-wrap

bpf:
	@clang -target bpf -O2 -g -Wall \
		-I./bpf -I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c bpf/portmux.bpf.c -o internal/bpf/portmux.bpf.o
	@echo "  BPF compiled"

agent: bpf
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(AGENT_BIN) ./cmd/agent/
	@echo "  Agent: $(AGENT_BIN)"

wrap:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(WRAP_BIN) ./cmd/wrap/
	@echo "  Wrapper: $(WRAP_BIN)"

build: bpf agent wrap

clean:
	rm -rf $(BUILD_DIR) internal/bpf/portmux.bpf.o
