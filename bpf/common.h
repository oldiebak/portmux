#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define MAGIC_PREFIX_DEFAULT 0xDEAD
#define MAX_WATCH_PORTS 8

struct agent_config {
    __u32 agent_ip;
    __u16 agent_port;
    __u16 magic_prefix;
    __u8  enabled;
    __u8  pad[3];
};
