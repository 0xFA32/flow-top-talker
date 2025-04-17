mod cli;
mod flow_info;
mod ebpf_handler;

use std::{
    thread::sleep,
    time::Duration,
    net::Ipv4Addr,
};

use flow_info::LimitedMaxHeap;

use crate::cli::Cli;
use crate::flow_info::FlowInfo;
use crate::ebpf_handler::EbpfHandler;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    env_logger::init();

    let mut ebpf_handler = EbpfHandler::init()?;
    ebpf_handler.add_config(&cli)?;
    ebpf_handler.attach()?;

    let mut heap = LimitedMaxHeap::new(cli.top_n);

    loop {
        sleep(Duration::from_secs(1));
        ebpf_handler.rotate_data(&mut heap)?;

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
