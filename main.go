package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gizak/termui/v3"
)

// Load the generated eBPF objects
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target amd64 -type syscall_val_t -type syscall_target_t -type outgoing_network_target_t bpf ebpf/main.c -- -I/usr/include/bpf

const windowSize = 40

var syscallNames = map[uint32]string{
	unix.SYS_EXECVE: "execve",
	unix.SYS_READ:   "read",
	unix.SYS_WRITE:  "write",
	unix.SYS_FSYNC:  "fsync",
	unix.SYS_OPEN:   "open",
	unix.SYS_OPENAT: "openat",
	unix.SYS_CLOSE:  "close",
	unix.SYS_FSTAT:  "fstat",
	unix.SYS_SOCKET: "socket",
	unix.SYS_POLL:   "poll",
}

func syscallNameToId(name string) (uint32, error) {
	for id, syscallName := range syscallNames {
		if syscallName == name {
			return id, nil
		}
	}
	return 0, fmt.Errorf("system call not found: %s", name)
}

func main() {
	var testLoad bool
	var outgoingTrafficInterface string

	// Define flags
	flag.BoolVar(&testLoad, "testLoad", false, "Test loading ebpf only")
	flag.StringVar(&outgoingTrafficInterface, "interface", "", "Specify the network interface to filter traffic on")

	// Parse the flags
	flag.Parse()

	// Handle --testLoad flag
	if testLoad {
		log.Println("Test loading ebpf only")
		return
	}

	// Collect remaining arguments
	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("Configuration file must be specified as the last argument")
	}

	// The last argument is the config file
	configFile := args[len(args)-1]
	log.Println("Loading configuration from file", configFile)

	config, err := ParseConfig(configFile)
	if err != nil {
		log.Fatalf("loading configuration: %v", err)
	}
	log.Println(config)

	// Handle --interface flag
	if outgoingTrafficInterface != "" {
		log.Println("Using network interface:", outgoingTrafficInterface)
	}

	linkManager, err := setupBpfAndProbes(config, outgoingTrafficInterface)
	if err != nil {
		log.Fatalf("setting up probes: %v", err)
	}
	defer linkManager.Close()

	if testLoad {
		log.Printf("Testload successful")
		os.Exit(0)
	}

	startPrometheusServer()

	ui, err := InitUI()
	if err != nil {
		log.Fatalf("initializing UI: %v", err)
	}
	defer ShutdownUI()

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for range ticker.C {
			updateMetrics(&linkManager.objs)
			updateSchedulerMetrics(&linkManager.objs)
			ui.Update(successArray[:], failureArray[:], contextSwitchArray[:], currentSyscallCounts)
		}
	}()
	defer ticker.Stop()

	uiEvents := termui.PollEvents()
	for {
		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return
		}
	}
}

var (
	successArray         [windowSize]float64
	failureArray         [windowSize]float64
	contextSwitchArray   [windowSize]float64
	lastSuccess          uint64
	lastFailure          uint64
	lastContextSwitch    uint64
	currentSyscallCounts = make(map[string][2]uint64)
	lastSyscallCounts    = make(map[string][2]uint64)
)

func updateSchedulerMetrics(objs *bpfObjects) {
	var key uint32 = 0
	var count uint64
	err := objs.ContextSwitchCountsT.Lookup(&key, &count)
	if err != nil {
		log.Printf("failed to lookup context switch count: %v", err)
		return
	}

	updatePrometheusContextSwitchMetrics(count)
	contextSwitchDelta := count - lastContextSwitch
	copy(contextSwitchArray[:], contextSwitchArray[1:])
	contextSwitchArray[windowSize-1] = float64(contextSwitchDelta)
	lastContextSwitch = count
}

func updateMetrics(objs *bpfObjects) {
	var key uint32
	var val bpfSyscallValT

	var newSuccessTotal uint64 = 0
	var newFailureTotal uint64 = 0

	currentSyscallCounts = make(map[string][2]uint64)

	iter := objs.SyscallCounts.Iterate()
	for iter.Next(&key, &val) {
		syscallName := syscallNames[uint32(key)]

		updatePrometheusMetrics(syscallName, val.Success, val.Failure)

		newSuccessTotal += val.Success
		newFailureTotal += val.Failure

		currentSyscallCounts[syscallName] = [2]uint64{val.Success, val.Failure}
	}

	if err := iter.Err(); err != nil {
		log.Printf("failed to iterate over map: %v", err)
	}

	successDelta := newSuccessTotal - lastSuccess
	failureDelta := newFailureTotal - lastFailure

	copy(successArray[:], successArray[1:])
	copy(failureArray[:], failureArray[1:])
	successArray[windowSize-1] = float64(successDelta)
	failureArray[windowSize-1] = float64(failureDelta)

	lastSuccess = newSuccessTotal
	lastFailure = newFailureTotal
}
