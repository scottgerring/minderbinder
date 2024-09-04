# Minderbinder

[![PR Check](https://github.com/scottgerring/minderbinder/actions/workflows/ci.yaml/badge.svg)](https://github.com/scottgerring/minderbinder/actions/workflows/ci.yaml)

_“Yossarian also thought Milo was a jerk; but he also know that Milo was a genius.”_

## What is this?
Minderbinder is a tool that uses eBPF to inject failures into running processes. 
Presently it can inject failures into **system calls** by attaching kprobes to the system call handler and failures into **outgoing network traffic** by attaching a traffic filter to Linux's traffic control subsystem. 

You can read a bit more about the motiviation and implementation details [in this blog entry](blog.scottgerring.com/introducing-minderbinder/ ). 

## What's it for?
Minderbinder aims to make it easy to generically inject failures into processes. At the moment you can write a config.yaml that describes the failures to inject and the processes to inject them into, start minderbinder, and see what happens. 

<details>
<summary>Video demo</summary>
	
[demo](https://github.com/user-attachments/assets/73cc8c3e-c447-4e0f-95c4-2e15d3f5fe70)

</details>

## Running Minderbinder
Check out [config.yaml](config.yaml) for a complete example. Minderbinder supports two different interventions - `syscall` and `outgoing_network`:

```yaml
agents_of_chaos:
  syscall:  
    # Stop curl from using `openat`
    - name: break_curl_openat
      syscall: openat
      ret_code: -2 # NOENT / no such file or directory
      targets:
        - process_name: curl
      delay_ms: 100 # Milliseconds to wait after the process starts. For openat, this gives the process a chance to start properly.
      failure_rate: 100
  outgoing_network:
    - name: break_wget_network
      targets:
        - process_name: wget
      delay_ms: 100 # Milliseconds. In this case, 100ms should be enough to get a DNS request through for the endpoint, before breaking the actual transfer to the HTTP server
      failure_rate: 100      
```

To run minderbinder, you specify the configuration file, and if you are using `outgoing_network`, the interface to attach to:
 ```bash
sudo ./minderbinder --interface enp67s0 config.yaml
```

Note: The graphs that pop up show general system call behaviour across the monitored values, and don't directly reflect the
actions minderbinder is performing on the targeted processes.

## How's it work?

Here's a helpful diagram! At a high level, the flow is:

* The user-space app reads the configuration file, attaches necessary probes, and writes the configuration into `syscall_target_config` and `outgoing_network_config` eBPF maps
* The `execve` kprobes catch new processes launching. Upon finding processes that match targets in the `_config` maps, they add the PID data to the target configuration and update the corresponding `_target` map. For example, a matched element in `syscall_target_config` leads to a PID+target configuration being added to `syscall_targets`
* The eBPF responsible for each module then fires for its particular hooks, and upon finding a relevant entry in its `_targets` map, and "breaks" the operation being considered accordingly

```mermaid
graph LR
    classDef mapClass fill:#f9f,stroke:#333,stroke-width:2px;
    classDef probeClass fill:#bbf,stroke:#333,stroke-width:2px;
    classDef mapLink stroke:#f9f,stroke-width:2px,stroke-dasharray: 5, 5;
    classDef defaultClass fill:#fff,stroke:#333,stroke-width:2px;

    subgraph "Configuration Maps"
        A[syscall_target_config]:::mapClass
        D[outgoing_network_config]:::mapClass
    end

    subgraph "App - Configuration Loading"
        F[Load Configuration]
        G[Load Syscall Targets]
        H[Load Outgoing Net Targets]

        F --> G --> A
        F --> H --> D
    end 

    subgraph "Runtime Maps"
        B[syscall_targets]:::mapClass
        E[outgoing_network_targets]:::mapClass
    end

    subgraph "execve Process Targeting"
        C[execve_data]:::mapClass
        L["Is Syscall Target?"]
        M["Is Outgoing Net Target?"]

        I["kprobe(execve)"]:::probeClass --> J["Record parent details"] --> C
        K["kretprobe(execve)"]:::probeClass --> L
        K --> M
        A -.-> L
        D -.-> M
        C -.-> L
        C -.-> M
        L --> B
        M --> E
    end

    subgraph "syscall Module"
         N["kprobe(targeted_syscall)"]:::probeClass 
         N --> O["Targeted process?"]
         B -.-> O
         O --> P["Delay past?"]
         P --> Q["Random chance met?"]
         Q --> R["bpf_override_return(err)"]
    end

   subgraph "TC Module"
        X["cgroup(sock_create)"]:::probeClass
        X --> Y["Targeted process?"]
        E -.->Y
        Y --> Z["Set socket mark"]

         S["tc(filter)"]:::probeClass 
         S --> T["Socket mark set?"]
         E -.-> T
         T --> U["Delay past?"]
         U --> V["Random chance met?"]
         V --> W["return TC_ACT_STOLEN"]
    end
```


## Big Picture

The long-term goal is to provide a back-end for existing unit test frameworks, so that we can write component tests that can trivially break the code under test in interesting, chaos-related fashions. This might look something like this:

```go
func TestYourAPIHandler_DownstreamFailure(t *testing.T) {
	// Create a new request
	req := httptest.NewRequest(http.MethodGet, "/your-api-endpoint", nil)

	// Record the response
	rec := httptest.NewRecorder()

	// Failure configuration
	cfg := FailureConfig{
		OutgoingNetwork: [] OutgoingNetworkFailure {
            {
                Protocol: "TCP",
                DestPort: 443,
                FailureRate: 100
            }
        }
	}

	// Wrap the actual handler call with Minderbinder. Because Minderbinder is injecting
    // failures into this process using eBPF, we don't need to elaborately craft stubs here;
    // we can setup the 
    minderbinder := &Minderbinder{}
	minderbinder.WithFailures(cfg, func() (*http.Response, error) {
		// Call the API handler
		YourAPIHandler(rec, req)
		return nil
	})

	// We should get a 502 / bad gateway back
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Equal(t, "Downstream service failed\n", rec.Body.String())
}

```

This gives us a mechanism to test our application and services resiliance in the face of failures. Traditionally we would do this either by extensively stubbing _all_ the interesting interfaces around the application and injecting failures, or, using some chaos engineering tool to inject failures into the entire aggregate system in a deployed cloud environment. Because Minderbinder leverages eBPF for the failure injection, the code needed for each supported language would be straightforward, as it would simply have to configure the native minderbinder component.

