#include <error.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "tracepoint_socket.skel.h"
#include "socket_trace.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
  exiting = true;
}

int handle_event(void* ctx, void *data, size_t data_sz)
{
  const struct write_info *e = data;
  printf("pid: %d \t syscall_nr: %d\t fd: %d\t count: %ld\t ret: %ld\t\n",
         e->common_pid, e->syscall_nr, e->fd, e->count, e->ret);
  return 0;
}

int main(int argc, char* argv[])
{
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  struct tracepoint_socket_bpf* skel = NULL;
  struct ring_buffer *rb = NULL;
  int err = 0;
  /* Load and verify BPF application */
  skel = tracepoint_socket_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /*Attach Tracepoint */
  err = tracepoint_socket_bpf__attach(skel);
  if(err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.write_events), handle_event, NULL, NULL);
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
  tracepoint_socket_bpf__destroy(skel);
  return 0;
}