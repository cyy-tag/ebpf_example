package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target amd64 bpf socket_recv.bpf.c -- -I../../../libbpf/src -I../../vmlinux/x86

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify listen port")
	}

	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println("port", port)
	//Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := loadBpf()
	if err != nil {
		panic(err)
	}
	spec.RewriteConstants(map[string]interface{}{
		"listen_port": uint16(port)})
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:    2,
			LogDisabled: false,
			LogSize:     10_000_00,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier error: %+v\n", ve)
			return
		}
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach the program to tracepoint
	// sys/kernel/debug/tracing/events/syscalls/sys_enter_read
	tp, err := link.Tracepoint("syscalls", "sys_enter_read", objs.SysEnterRead, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()
	// sys/kernel/debug/tracing/events/syscalls/sys_exit_read
	tp1, err := link.Tracepoint("syscalls", "sys_exit_read", objs.SysExitRead, nil)
	if err != nil {
		log.Fatalf("openint tracepoint: %s", err)
	}
	defer tp1.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("tick ... ")
	for range ticker.C {
		log.Println("tick ... ")
	}
}
