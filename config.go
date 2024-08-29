package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AgentsOfChaos AgentsOfChaos `yaml:"agents_of_chaos"`
}

type AgentsOfChaos struct {
	Syscall         []SyscallConfig                `yaml:"syscall"`
	OutgoingNetwork []ProcessOutgoingNetworkConfig `yaml:"outgoing_network"`
	IncomingNetwork []SystemIncomingNetworkConfig  `yaml:"incoming_network"`
}

type SyscallConfig struct {
	Name        string   `yaml:"name"`
	Syscall     string   `yaml:"syscall"`
	RetCode     int      `yaml:"ret_code"`
	Targets     []Target `yaml:"targets"`
	DelayMs     int      `yaml:"delay_ms"`
	FailureRate int      `yaml:"failure_rate"`
}

type ProcessOutgoingNetworkConfig struct {
	Name        string   `yaml:"name"`
	Targets     []Target `yaml:"targets"`
	DelayMs     int      `yaml:"delay_ms"`
	FailureRate int      `yaml:"failure_rate"`
}

type SystemIncomingNetworkConfig struct {
	Name        string `yaml:"name"`
	DelayMs     int    `yaml:"delay_ms"`
	FailureRate int    `yaml:"failure_rate"`
}

type Target struct {
	ProcessName string `yaml:"process_name,omitempty"`
}

func ParseConfig(file string) (*Config, error) {
	var config Config

	fileBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(fileBytes, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
