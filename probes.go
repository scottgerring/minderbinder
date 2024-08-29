package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type LinkManager struct {
	objs      bpfObjects
	links     []link.Link
	netfilter []netlink.Filter
}

func (lm *LinkManager) Add(links ...link.Link) {
	lm.links = append(lm.links, links...)
}

func (lm *LinkManager) Close() {
	for _, l := range lm.links {
		l.Close()
	}

	for _, l := range lm.netfilter {
		err := netlink.FilterDel(l)
		if err != nil {
			log.Printf("Failed deleting TC filter")
		}
	}

	lm.objs.Close()
}

// Alternative to loadBpfObjects that rewrites constants for us
func loadObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

func setupBpfAndProbes(config *Config, outgoingTrafficInterface string) (*LinkManager, error) {
	linkManager := &LinkManager{}

	linkManager.objs = bpfObjects{}
	if err := loadObjects(&linkManager.objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	// Validate the config
	validateConfig(config, outgoingTrafficInterface)

	// Attach everything
	tracepoints, err := attachTracepoints(&linkManager.objs)
	if err != nil {
		return nil, err
	}
	linkManager.Add(tracepoints...)
	kprobes, err := attachKprobes(&linkManager.objs, config)
	if err != nil {
		return nil, err
	}
	linkManager.Add(kprobes...)
	err = attachTcProbes(&linkManager.objs, config, outgoingTrafficInterface, linkManager)
	if err != nil {
		return nil, err
	}

	// Load probe information into the maps
	if err := loadProbeInfo(&linkManager.objs, config); err != nil {
		return nil, err
	}

	return linkManager, nil
}

// Get uptime in nanoseconds
func uptime() (uint64, error) {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0, err
	}
	uptime := uint64(info.Uptime) * uint64(time.Second.Nanoseconds())
	return uptime, nil
}

// Get current timestamp in nanoseconds since boot
func timestampSinceBoot() (uint64, error) {
	uptimeNs, err := uptime()
	if err != nil {
		return 0, err
	}
	currentTimeNs := uint64(time.Now().UnixNano())
	bootTimeNs := currentTimeNs - uptimeNs
	return bootTimeNs, nil
}

// Validates config before we load it
func validateConfig(config *Config, outgoingTrafficInterface string) {

	// If we have any outgoing network configuration at all, we need an outgoing traffic interface
	if len(config.AgentsOfChaos.OutgoingNetwork) > 0 && outgoingTrafficInterface == "" {
		log.Fatalf("outgoing_network configurations provided, but no --interface argument given")
	}
}

func loadProbeInfo(objs *bpfObjects, config *Config) error {

	// Get curent time in nanoseconds since boot. We will use this to anchor any "not before"
	// probes.
	_, err := timestampSinceBoot()
	if err != nil {
		return err
	}

	// For our --testLoad mode we won't load with any config
	if config == nil {
		return nil
	}

	for _, syscall := range config.AgentsOfChaos.Syscall {

		syscallId, err := syscallNameToId(syscall.Syscall)
		if err != nil {
			return err
		}

		for _, target := range syscall.Targets {
			// Are we targeting a comm or a PID?
			if target.ProcessName != "" {
				log.Printf("Loading syscall target: %s, comm=%s", syscall.Syscall, target.ProcessName)

				key := padStringToLength(target.ProcessName, 1024)

				// Long winded initialization cuz of nested anon struct
				value := bpfSyscallTargetT{
					TargetIsActive: 1,
				}
				value.FailureConfig.DelayAfterStartNs = uint64(syscall.DelayMs) * 1_000_000
				value.FailureConfig.FailureRatePercent = uint32(syscall.FailureRate)
				value.FailureConfig.InjectedRetCode = uint32(syscall.RetCode)
				value.FailureConfig.SyscallId = syscallId

				// Update the map with the new target data
				if err := objs.SyscallTargetConfig.Update(key, value, ebpf.UpdateAny); err != nil {
					return err
				}
			}
		}
	}

	for _, outgoingNet := range config.AgentsOfChaos.OutgoingNetwork {
		for _, target := range outgoingNet.Targets {
			// Are we targeting a comm or a PID?
			if target.ProcessName != "" {
				log.Printf("Loading outgoing_network target: comm=%s", target.ProcessName)

				key := padStringToLength(target.ProcessName, 1024)

				// Long winded initialization cuz of nested anon struct
				value := bpfOutgoingNetworkTargetT{}
				value.FailureConfig.TargetIsActive = 1
				value.FailureConfig.DelayAfterStartNs = uint64(outgoingNet.DelayMs) * 1_000_000
				value.FailureConfig.FailureRatePercent = uint32(outgoingNet.FailureRate)

				// Update the map with the new target data
				if err := objs.OutgoingNetworkTargetConfig.Update(key, value, ebpf.UpdateAny); err != nil {
					return err
				}
			} else {
				log.Fatalf("Error: outgoing_network doesn't yet support process ID targeting for outgoing net target %s", outgoingNet.Name)
			}
		}
	}

	return nil
}

func padStringToLength(input string, totalByteCount int) []byte {
	// Create a slice with the specified total length
	result := make([]byte, totalByteCount)

	// Copy the input string into the slice
	copy(result, input)

	// Return the padded slice
	return result
}

// Returns a list of all syscalls that are actually
// referenced by the given config
func getUniqueSyscalls(config *Config) []string {

	if config == nil {
		return make([]string, 0)
	}

	syscallSet := make(map[string]bool)

	for _, syscall := range config.AgentsOfChaos.Syscall {
		if _, found := syscallSet[syscall.Syscall]; !found {
			syscallSet[syscall.Syscall] = true
		}
	}

	uniqueSyscalls := make([]string, 0, len(syscallSet))
	for key := range syscallSet {
		uniqueSyscalls = append(uniqueSyscalls, key)
	}

	return uniqueSyscalls

}

func attachTracepoints(objs *bpfObjects) ([]link.Link, error) {
	var tracepoints []link.Link

	tpInfo := []struct {
		category string
		name     string
		program  *ebpf.Program
	}{
		{"syscalls", "sys_exit_execve", objs.SysExitSyscall},
		{"syscalls", "sys_exit_poll", objs.SysExitSyscall},
		{"syscalls", "sys_exit_read", objs.SysExitSyscall},
		{"syscalls", "sys_exit_socket", objs.SysExitSyscall},
		{"syscalls", "sys_exit_write", objs.SysExitSyscall},
		{"syscalls", "sys_exit_open", objs.SysExitSyscall},
		{"syscalls", "sys_exit_close", objs.SysExitSyscall},
		{"syscalls", "sys_exit_fsync", objs.SysExitSyscall},
		{"sched", "sched_switch", objs.SchedSwitch},
	}

	for _, tp := range tpInfo {
		log.Printf("Attaching tracepoint %s/%s", tp.category, tp.name)
		tpLink, err := link.Tracepoint(tp.category, tp.name, tp.program, nil)
		if err != nil {
			log.Printf("Error attaching tracepoint %s/%s: %v", tp.category, tp.name, err)
			return nil, err
		}
		tracepoints = append(tracepoints, tpLink)
	}

	return tracepoints, nil
}

func attachKprobes(objs *bpfObjects, config *Config) ([]link.Link, error) {
	var kprobes []link.Link

	kpInfo := []struct {
		retProbe bool
		name     string
		program  *ebpf.Program
	}{
		{false, "sys_execve", objs.KprobeSysExecve},
		{true, "sys_execve", objs.KretprobeSysExecve},
	}

	// Map all our syscalls up
	// Adding entries for each syscall in syscallNames
	for _, name := range getUniqueSyscalls(config) {
		kpInfo = append(kpInfo, struct {
			retProbe bool
			name     string
			program  *ebpf.Program
		}{false, "sys_" + name, objs.KprobeInterceptSyscall})
	}

	for _, kp := range kpInfo {
		if !kp.retProbe {
			log.Printf("Attaching kprobe %s", kp.name)
			kpLink, err := link.Kprobe(kp.name, kp.program, nil)
			if err != nil {
				log.Fatalf("Error attaching kprobe %s: %v", kp.name, err)
				return nil, err
			}
			kprobes = append(kprobes, kpLink)
		} else {
			log.Printf("Attaching kretprobe %s", kp.name)
			kpLink, err := link.Kretprobe(kp.name, kp.program, nil)
			if err != nil {
				log.Fatalf("Error attaching kretprobe %s: %v", kp.name, err)
				return nil, err
			}
			kprobes = append(kprobes, kpLink)
		}
	}

	return kprobes, nil
}

func attachTcProbes(objs *bpfObjects, config *Config, outgoingTrafficInterface string, linkManager *LinkManager) error {

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatalf("Failed detecting cgroup path: %s", err)
	}

	// Attach socket create program
	// We use this to mark sockets created by a given PID
	log.Printf("Attaching cgroup sock_create")
	sockCreate, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.CreateSocket,
	})
	if err != nil {
		log.Fatalf("Failed attaching sockCreate program: %s", err)
	}
	linkManager.links = append(linkManager.links, sockCreate)

	// Attach the TC filter
	// We use this to drop traffic
	tcFilter, err := attachFilter(outgoingTrafficInterface, objs.TcFilterTraffic)
	if err != nil {
		log.Fatalf("Failed attaching TC filter: %s", err)
	}
	linkManager.netfilter = append(linkManager.netfilter, tcFilter)

	// This doesn't work
	// defer netlink.FilterDel(tc_filter)
	return nil
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

func attachFilter(attachTo string, program *ebpf.Program) (netlink.Filter, error) {
	log.Printf("Attaching to interface %s", attachTo)

	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return nil, fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},

		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return nil, fmt.Errorf("could not get replace qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("failed to replace tc filter: %w", err)
	}

	return filter, nil
}
