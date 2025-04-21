# Flow top talker

An eBPF-based tool that displays top-talker flows ranked by throughput.

**Note:** This project was built for learning purposes and is intentionally over-engineered to explore various design ideas.

## Usage

```
Usage: flow-top-talker [OPTIONS] --top-n <TOP_N>

Options:
  -n, --top-n <TOP_N>  Provide the top N flows
  -p, --pid <PID>      Filter by process id
  -t, --tid <TID>      Filter by thread id
  -x, --host-name      Display hostname. By default Ip address would be displayed
  -h, --help           Print help
  -V, --version        Print version
```

## Demo

![Demo](assets/demo.gif)

## Building the project

### Pre-requisites 

1. sudo apt install libzstd-dev
2. sudo apt install libpolly-20-dev
3. Install LLVM-20

```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 20
```

4. export LLVM_SYS_200_PREFIX=/usr/lib/llvm-20

5. Install bpf-linker

```cargo install --no-default-features bpf-linker```

### Running it locally

1. cargo build
2. cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --top-n 10

## Structure of the project

The tool is built using aya so it follows the a typical aya project structure. Following are the steps to setup initial project

### Setting up initial project

Aya provides a template to setup project structure with some boilerplate code.

1. sudo apt install pkg-config libssl-dev
2. cargo install cargo-generate
3. For kprobe based project use following template,

```cargo generate --name flow-top-talker -d program_type=kprobe https://github.com/aya-rs/aya-template```

### [Crate] flow-top-talker

A user-space program that loads the eBPF program and attaches it to the required kprobes. The eBPF program captures flow information using a `PerCpuHashMap`, which is then aggregated in the user-space program and added to a fixed-size max heap sorted by throughput.

Flow information is already separated into ingress and egress, and each is displayed in its own section in a terminal-based TUI (check out the demo).

Data is refreshed every second using a double-buffering strategy. Every 1 second, the user-space program sets a flag (stored in another eBPF array of size 1), which the eBPF program uses to decide which `PerCpuHashMap` to write to. Meanwhile, the user-space program reads from the previous `PerCpuHashMap`, aggregates and displays the data, and clears the map. This avoids synchronization complexity and makes the tool easier to extend.

The tool also supports filtering based on user-provided input such as Process ID or Thread ID. These filters are passed to the eBPF program to prevent irrelevant flow data from being added to the PerCpuHashMap.

### [Crate] flow-top-talker-common

This crate defines the common types used by both the eBPF and user-space program. Currently, it primarily defines the keys used in the eBPF map.

### [Crate] flow-top-talker-ebpf

The eBPF program which attaches to the kernel functions `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, and `udp_recvmsg` via kprobes at their entry points. All of these kernel functions have a `sock` pointer as the first argument and `size` as the third argument. From the `sock` structure, the 5-tuple information [src_addr, dest_addr, src_port, dest_port, and protocol] can be extracted, and the `size` is used to calculate throughput. The `aya-tool` is used to generate Rust bindings, which are then used to extract relevant information.

Depending on the flag set by the user-space program, the eBPF program adds the 5-tuple and size to the appropriate `PerCpuHashMap`. The flag is read using `read_volatile` and the value of the flag is solely controlled by the user-space program and is not read by the user program after initialization (it uses local value to update). Which is sufficient; no additional memory fences or barriers are required.

The eBPF program does not remove any data from the maps; it expects the user-space program to do so. Since eBPF maps must be fixed-size, if the user program becomes unresponsive, flow data collection will stop, but there will be no further impact on the system.

The eBPF program also filters flows based on the configuration provided by the user. Currently, it captures only IPv4 traffic.

## TODO

1. Calculate avg throughput.
2. Add more filters to the tool.
3. Add number of packets apart from throughput.
