package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf xdp_print.bpf.c -- -I../../../../libbpf/src -I../../../vmlinux/x86

func main() {

	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
		return
	}
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	//Load pre-compiled programs and maps into kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
		return
	}
	defer objs.Close()

	op := link.XDPOptions{
		Program:   objs.XdpProgSimple,
		Interface: iface.Index,
	}

	l, err := link.AttachXDP(op)
	if err != nil {
		log.Fatalf("attach xdp failed %v", err)
		return
	}
	defer l.Close()

	exit := false
	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper
		exit = true
	}()

	for !exit {
		time.Sleep(time.Second)
	}
}
