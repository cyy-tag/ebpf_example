OUTPUT := .output
CLANG ?= clang
LLVM_STRPIP ?= llvm-strip
BPFTOOL ?= bpftool
LIBBPF_SRC := $(abspath ../../libbpf/src)
LIBBPF_INCLUDE := $(abspath ../../libbpf/include/uapi)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
INCLUDES := -I$(LIBBPF_INCLUDE) -I$(OUTPUT) -I$(OUTPUT)/bpf -I../vmlinux/$(ARCH)
APPS = ringbuffer hello-buffer-config tracepoint_socket

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(APPS)

# Build final application
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

# Build user-space code
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c, $^) -o $@

$(patsubst %, $(OUTPUT)/%.o, $(APPS)): %.o: %.skel.h

# Build BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) common.h | $(OUTPUT)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		\
			$(INCLUDES) -c $(filter %.c, $^) -o $@
	$(Q)$(LLVM_STRPIP) -g $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)
