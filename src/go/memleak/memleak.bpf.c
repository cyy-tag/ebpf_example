//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include "maps.bpf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240


const volatile u64 stack_flags = 0;

struct alloc_info {
    u64 size;
    u64 timestamp_ns;
    int stack_id;
};

union combined_alloc_info {
    struct {
        u64 total_size : 40;
        u64 number_of_allocs : 24;
    };
    u64 bits;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* address */
    __type(value, struct alloc_info);
    __uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* stack id */
    __type(value, union combined_alloc_info);
    __uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
} stack_traces SEC(".maps");


static union combined_alloc_info initial_cinfo;

static void update_statistics_add(u64 stack_id, u64 sz)
{
    union combined_alloc_info *existing_cinfo;
}

static inline int gen_alloc_enter(size_t size)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tid = bpf_get_current_pid_tgid();
    u64 size64 = size;
    
    bpf_printk("alloc entered, size = %u\n", size);
    return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct alloc_info info = {0};
    
    info.timestamp_ns = bpf_ktime_get_ns();
    info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);
}

struct combined_alloc_info_t {
    u64 total_size;
    u64 number_of_allocs;
};

SEC("uprobe/malloc")
int BPF_UPROBE(malloc_enter, size_t size)
{

}

SEC("uretprobe/malloc")
int BPF_URETPROBE(malloc_exit, void* address)
{

}


SEC("uprobe/free")
int BPF_UPROBE(free_enter, void* address)
{

}

SEC("uprobe/calloc")
int BPF_UPROBE(calloc_enter, size_t nmemb, size_t size)
{

}

SEC("uretprobe/calloc")
int BPF_URETPROBE(calloc_exit, void* address)
{

}

SEC("uprobe/realloc")
int BPF_UPROBE(realloc_enter, void *ptr, size_t size)
{

}

SEC("uretprobe/realloc")
int BPF_URETPROBE(realloc_exit)
{

}

