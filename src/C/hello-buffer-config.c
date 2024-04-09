#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "hello-buffer-config.h"
#include "hello-buffer-config.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
  exiting = true;
}

void handle_event(void *ctx, int cpu,
				      void *data, __u32 size)
{
    const struct data_t* d = data;
    printf("pid: %d\tuid: %d\tcommand: %s\tmessage: %s\tpath: %s\n",
      d->pid, d->uid, d->command, d->message,d->path);
}

void lost_event(void *ctx, int cpu, __u64 cnt)
{
  printf("lost_event cpu %d cnt %lld", cpu, cnt);
}


int main()
{
  struct hello_buffer_config_bpf *skel;
  struct perf_buffer *pb = NULL;
  int err = 0;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  skel = hello_buffer_config_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /*attach*/
  err = hello_buffer_config_bpf__attach(skel);
  if(err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  /*Set up event output*/
  pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event,
              lost_event, NULL, NULL);
  if (!pb) {
    err = -1;
    fprintf(stderr, "Failed to create perf_event_output\n");
    goto cleanup;
  }

  while(!exiting) {
    err = perf_buffer__poll(pb, 100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      fprintf(stderr, "Error polling perf_event_output\n");
      break;
    }
  }
cleanup:
  perf_buffer__free(pb);
  hello_buffer_config_bpf__destroy(skel);
  return err;
}
