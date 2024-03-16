#include <error.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ringbuffer.skel.h"
#include "common.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int handle_event(void* ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("pid: %d\tcomm: %s\n", e->pid, e->comm);

    return 0;
}

int main(int argc, char* argv[])
{
    struct ring_buffer *rb = NULL;
    struct ringbuffer_bpf *skel = NULL;
    int err = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = ringbuffer_bpf__open_and_load();
    if(!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    /* Attach Kprobe function */
    err = ringbuffer_bpf__attach(skel);
    if(err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;       
    }
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    while(!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms*/);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }
cleanup:
	ring_buffer__free(rb);
    ringbuffer_bpf__destroy(skel);
    return 0;
}