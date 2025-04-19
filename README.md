# flow-top-talker

Ebpf based tool to provide top N flows on a host based on ingress or egress.

### Setting up bpf-linker

Pre-requisites to installing bpf-linker

1. sudo apt install libzstd-dev
2. sudo apt install libpolly-20-dev
3. Install LLVM-20

```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 20
```

4. export LLVM_SYS_200_PREFIX=/usr/lib/llvm-20

Install bpf-linker

```cargo install --no-default-features bpf-linker```

### Setting up initial project

Use latest rustup.

1. sudo apt install pkg-config libssl-dev
2. cargo install cargo-generate
3. For xdp based project use following template,

```cargo generate --name flow-top-talker -d program_type=xdp https://github.com/aya-rs/aya-template```

### Running it locally

1. cargo build
2. cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --top-n 10

### Usage

![Demo](assets/demo.gif)

### TODO

1. Calculate avg throughput.
2. Cache padding in FlowKey.
3. Add more filters to the tool.
