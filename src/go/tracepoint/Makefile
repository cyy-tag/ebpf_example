
.PHONY: all

build: main.go socket_recv.bpf.c
	go generate && go build

remote_test: tracepoint
	scp -i /root/.ssh/remote_id_rsa -P 60522 tracepoint root@172.30.172.172:ebpf_tc_test/ && \
	ssh -i /root/.ssh/remote_id_rsa -t root@172.30.172.172 -p 60522  './ebpf_tc_test/tracepoint 2333; bash'

local_test: tracepoint
	./tracepoint 2333