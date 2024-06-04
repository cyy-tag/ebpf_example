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
  // const struct data_args_t *e = data;
  // printf("pid: %d\t fn: %d\t fd: %d\t count: %ld\t ret: %ld\t\n",
  //        e->pid, e->source_fn, e->fd, e->count, e->ret);
  return 0;
}

int handle_upd_event(void* ctx, void *data, size_t data_sz)
{
  const struct udp_args_t *e = data;
  printf("pid: %d\t family: %u\t fn: %d\t addr: %d\t port: %d\t count: %ld\t ret: %ld\t\n",
      e->pid, e->sa_family, e->source_fn, e->sin_addr, e->sin_port, e->count, e->ret);
  return 0;
}

int main(int argc, char* argv[])
{
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  struct tracepoint_socket_bpf* skel = NULL;
  struct ring_buffer *rb = NULL;
  struct ring_buffer *udp_rb = NULL;
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
  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  /* Set up UDP ring buffer */
  udp_rb = ring_buffer__new(bpf_map__fd(skel->maps.udp_events), handle_upd_event, NULL, NULL);
  if(!udp_rb) {
    err = -1;
    fprintf(stderr, "Failed to create upd ring buffer\n");
    goto cleanup;
  }
  int err1 = 0;
  while(!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms*/);
    err1 = ring_buffer__poll(udp_rb, 100 /* timeout, ms*/);
    if (err == -EINTR || err1 == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0 || err1 < 0) {
      printf("Error polling ring buffer: %d\n", err);
      break;
    }
  }
cleanup:
  ring_buffer__free(rb);
  ring_buffer__free(udp_rb);
  tracepoint_socket_bpf__destroy(skel);
  return 0;
}