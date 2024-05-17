package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf tcx.bpf.c -- -I/usr/include/x86_64-linux-gnu -I../../../../libbpf/src
func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Please specify a network interface and http port")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	spec, err := loadBpf()
	if err != nil {
		panic(err)
	}

	spec.RewriteConstants(map[string]interface{}{
		"listen_port": uint64(port)})

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:    0,
			LogDisabled: false,
			LogSize:     10_000_00,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier error: %+v\n", ve)
			return
		}
		log.Fatalf("load program err: %+v", err)
	}
	defer objs.Close()

	// Attach the program to Ingress TC.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressProgFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)

	// Attach the program to Egress TC.
	l2, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressProgFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer l2.Close()

	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("ticker .\n")
	}
}
