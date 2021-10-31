CARGO = cargo
RUNNER = sudo -E

RUN_ARGS = # User provided args could go here, or be specified at cmd line

DEBUG   = target/debug/kprobes-args-test
RELEASE = target/release/kprobes-args-test

DEBUG_BPF   = target/bpfel-unknown-none/debug/kprobes-args-test
RELEASE_BPF = target/bpfel-unknown-none/release/kprobes-args-test

USER_SRCS   =  $(wildcard kprobes-args-test-common/*) $(wildcard kprobes-args-test-common/**/*)
COMMON_SRCS =  $(wildcard kprobes-args-test/*) $(wildcard kprobes-args-test/**/*)
BPF_SRCS    =  $(wildcard kprobes-args-test-ebpf/*) $(wildcard kprobes-args-test-ebpf/**/*)

.PHONY: build
build: $(DEBUG)

.PHONY: run
run: $(DEBUG)
	$(RUNNER) ./$(DEBUG) --path $(DEBUG_BPF) $(RUN_ARGS)

.PHONY: build-release
build-release: $(RELEASE)

.PHONY: run-release
run-release: $(RELEASE)
	$(RUNNER) ./$(RELEASE) --path $(RELEASE_BPF) $(RUN_ARGS)

.PHONY: clean
clean:
	$(CARGO) clean

$(DEBUG): $(DEBUG_BPF) $(USER_SRCS) $(COMMON_SRCS)
	$(CARGO) build

$(DEBUG_BPF): $(BPF_SRCS) $(COMMON_SRCS)
	$(CARGO) xtask build-ebpf

$(RELEASE): $(RELEASE_BPF) $(USER_SRCS) $(COMMON_SRCS)
	$(CARGO) build --release

$(RELEASE_BPF): $(BPF_SRCS) $(COMMON_SRCS)
	$(CARGO) xtask build-ebpf --release
