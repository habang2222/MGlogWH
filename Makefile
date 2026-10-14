# Build against a pinned libbpf-bootstrap checkout beside this repository.
# Both paths can be overridden for a different installation layout.
BOOTSTRAP ?= $(abspath $(CURDIR)/../libbpf-bootstrap)
BUILD ?= $(CURDIR)/build
.DELETE_ON_ERROR:
LIBDIR := $(BOOTSTRAP)/examples/c/.output
BPFTOOL := $(LIBDIR)/bpftool/bootstrap/bpftool
INC := -I$(LIBDIR) -I$(BOOTSTRAP)/libbpf/include/uapi -I$(BOOTSTRAP)/vmlinux.h/include/x86

all: $(BUILD)/collector
$(BUILD):
	mkdir -p $@
$(BUILD)/sensor.bpf.o: sensor.bpf.c event.h tenant.h quarantine.h rules.h | $(BUILD)
	clang -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 $(INC) -c $< -o $@
$(BUILD)/sensor.skel.h: $(BUILD)/sensor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@
$(BUILD)/collector: collector.c event.h tenant.h quarantine.h rules.h $(BUILD)/sensor.skel.h
	cc -g -O2 -Wall -Wextra -Werror -Wno-unused-parameter -pthread $(INC) -I$(BUILD) collector.c $(LIBDIR)/libbpf.a -lelf -lz -o $@
.PHONY: all
$(BUILD)/test_writer: test_writer.c collector.c event.h tenant.h quarantine.h rules.h $(BUILD)/sensor.skel.h
	cc -g -O2 -Wall -Wextra -Werror -Wno-unused-parameter -pthread $(INC) -I$(BUILD) test_writer.c $(LIBDIR)/libbpf.a -lelf -lz -o $@
$(BUILD)/test_quarantine: test_quarantine.c quarantine.h event.h | $(BUILD)
	cc -g -O2 -Wall -Wextra -Werror test_quarantine.c -o $@
$(BUILD)/test_rules: test_rules.c rules.h quarantine.h event.h | $(BUILD)
	cc -g -O2 -Wall -Wextra -Werror test_rules.c -o $@
test: $(BUILD)/test_writer $(BUILD)/test_quarantine $(BUILD)/test_rules
	$(BUILD)/test_writer
	$(BUILD)/test_quarantine
	$(BUILD)/test_rules
	python3 -m unittest -v test_manage
	python3 -m unittest -v test_ledger
	python3 validation/2026-10-14/test_benchmark_portable.py
.PHONY: test
