mod cli;
mod flow_info;
mod ebpf_handler;

use std::{
    collections::BinaryHeap,
    thread::sleep,
    time::Duration,
    net::Ipv4Addr,
};

use flow_info::add_to_heap;

use crate::cli::Cli;
use crate::flow_info::FlowInfo;
use crate::ebpf_handler::EbpfHandler;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let top_n = cli.top_n;

    env_logger::init();

    let mut ebpf_handler = EbpfHandler::init()?;
    ebpf_handler.update_config(&cli)?;
    ebpf_handler.attach()?;

    let mut heap: BinaryHeap<FlowInfo> = BinaryHeap::new();

    loop {
        sleep(Duration::from_secs(1));
        ebpf_handler.rotate_data(&mut heap, top_n)?;

        println!("--------------Printing Flow info--------------------");
        for flow_info in heap.iter() {
            println!("{:?}:{} --> {:?}:{}  [{} Bps]",
                Ipv4Addr::from(flow_info.src_addr),
                flow_info.src_port,
                Ipv4Addr::from(flow_info.dest_addr),
                flow_info.dest_port,
                flow_info.throughput,
            );
        }
        println!("--------------Done printing Flow info--------------------");

        heap.clear();
    }

    Ok(())
}
