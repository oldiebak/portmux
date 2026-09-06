// Package bpf provides embedded eBPF program loading.
// Build requires: clang -target bpf -O2 -g -c bpf/portmux.bpf.c -o internal/bpf/portmux.bpf.o -I/usr/include -I/usr/include/x86_64-linux-gnu
package bpf
