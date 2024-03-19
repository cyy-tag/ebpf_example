package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type alloc_info bpf memleak.bpf.c -- -I../../../libbpf/src -I../../vmlinux/x86

type funcHook struct {
	Symbol string
	Prog   *ebpf.Program
}

const (
	// The path to the ELF binary containing the function to trace.
	binPath = "/lib/x86_64-linux-gnu/libc.so.6"
)

func main() {

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled program and maps into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// define hook
	uprobeFuncHooks := []funcHook{
		funcHook{Symbol: "malloc", Prog: objs.MallocEnter},
		funcHook{Symbol: "free", Prog: objs.FreeEnter},
	}
	uretprobeFuncHooks := []funcHook{
		funcHook{Symbol: "malloc", Prog: objs.MallocExit},
	}
	// Open an ELF binary and read its symbols
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatal("opening executable: %s", err)
	}

	// attach Uprobe
	for _, hook := range uprobeFuncHooks {
		up, err := ex.Uprobe(hook.Symbol, hook.Prog, nil)
		if err != nil {
			log.Fatalf("creating uprobe %s", hook.Symbol)
		}
		defer up.Close()
	}

	// attach uretprobe
	for _, hook := range uretprobeFuncHooks {
		up, err := ex.Uretprobe(hook.Symbol, hook.Prog, nil)
		if err != nil {
			log.Fatalf("creating uretprobe %s", hook.Symbol)
		}
		defer up.Close()
	}

	// Wait for a signal and close
	<-stopper
	log.Println("Received signal, existing program...")
}
