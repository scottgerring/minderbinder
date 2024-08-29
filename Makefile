all: minderbinder

clean:
	rm -f minderbinder
	rm -f bpf_x86_bpfel.go
	rm -f *.o

minderbinder: $(wildcard *.go) bpf_x86_bpfel.o
	go build

bpf_x86_bpfel.o: ebpf/main.c
	go generate

# 
# Debugging targets
#
testload: minderbinder
	sudo ./minderbinder --testLoad

watch:
	while true; do \
		$(MAKE) testload; \
		inotifywait -qre close_write .; \
	done

ebpf_only: ebpf/main.c
	clang -c ebpf/main.c
