#include <error.h>
#include <bpf/libbpf.h>

struct config {
  enum xdp_attach_mode attach_mode;
}


int main(int argc, char* argv[])
{
  //define xdp program
  struct xdp_program *program;
  int err;

}

