mod cli;
mod flow_info;

use std::{
    collections::BinaryHeap,
    thread::sleep,
    time::Duration,
    net::Ipv4Addr,
};

use anyhow::anyhow;
use aya::{
    maps::{
        Array, HashMap, MapData, MapError, PerCpuHashMap
    }, programs::KProbe, util::nr_cpus, Ebpf
};
use flow_info::add_to_heap;
use flow_top_talker_common::common_types::{
    ConfigKey, FlowKey, CONFIG_MAP_NAME, EGRESS_TRACKER_0_MAP_NAME, EGRESS_TRACKER_1_MAP_NAME, FLAG_MAP_NAME, INGRESS_TRACKER_0_MAP_NAME, INGRESS_TRACKER_1_MAP_NAME
};

use crate::cli::Cli;
use crate::flow_info::FlowInfo;
use clap::Parser;

#[rustfmt::skip]
use log::{debug, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let top_n = cli.top_n;

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/flow-top-talker"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    
    let nr_cpus = nr_cpus();
    if nr_cpus.is_err() {
        eprintln!("Not able to get possible CPU. Exiting early..");
        return Ok(());
    }

    update_config(&mut ebpf, &cli)?;
    let nr_cpus = nr_cpus.unwrap();

    attach_to_beginning(&mut ebpf, "tcp_sendmsg_kprobe", "tcp_sendmsg")?;
    attach_to_beginning(&mut ebpf, "tcp_recvmsg_kprobe", "tcp_recvmsg")?;
    attach_to_beginning(&mut ebpf, "udp_sendmsg_kprobe", "udp_sendmsg")?;
    attach_to_beginning(&mut ebpf, "udp_recvmsg_kprobe", "udp_recvmsg")?;

    
    let mut heap: BinaryHeap<FlowInfo> = BinaryHeap::new();

    loop {
        sleep(Duration::from_secs(1));
        match ebpf.map_mut(FLAG_MAP_NAME) {
            Some(map) => {
                let mut array: Array<&mut _, u32> = Array::try_from(map).unwrap();
                let flag = array.get(&0, 0).unwrap();

                if flag == 0 {
                    let _ = array.set(0, 1, 0);
                    fetch_latest_data(&mut ebpf, nr_cpus, INGRESS_TRACKER_0_MAP_NAME, &mut heap, top_n);
                    fetch_latest_data(&mut ebpf, nr_cpus, EGRESS_TRACKER_0_MAP_NAME, &mut heap, top_n);
                } else {
                    let _ = array.set(0, 0, 0);
                    fetch_latest_data(&mut ebpf, nr_cpus, INGRESS_TRACKER_1_MAP_NAME, &mut heap, top_n);
                    fetch_latest_data(&mut ebpf, nr_cpus, EGRESS_TRACKER_1_MAP_NAME, &mut heap, top_n);
                }
            },
            None => { continue }
        };

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

fn update_config(
    ebpf: &mut Ebpf,
    cli: &Cli
) -> anyhow::Result<()> {
    match ebpf.map_mut(CONFIG_MAP_NAME) {
        Some(map) => {
            let mut map_data: HashMap<&mut MapData, ConfigKey, u64> =
                HashMap::try_from(map).unwrap();
            
            if let Some(pid) = cli.pid {
                map_data.insert(ConfigKey::PID, pid, 0)?;
            }

            if let Some(tid) = cli.tid {
                map_data.insert(ConfigKey::TID, tid, 0)?;
            }

            return Ok(());
        },
        None => {
            return Err(anyhow!("Failed to read config map name"));
        }
    }
}

fn fetch_latest_data(
    ebpf: &mut Ebpf,
    nr_cpus: usize,
    map_name: &str, 
    heap: &mut BinaryHeap<FlowInfo>,
    top_n: usize,
) {
    match ebpf.map_mut(map_name) {
        Some(map) => {
            let mut map_data: PerCpuHashMap<&mut MapData, FlowKey, u64> =
                PerCpuHashMap::try_from(map).unwrap();
            let keys: Vec<Result<FlowKey, MapError>> = map_data.keys().collect();
            for key in keys {
                if let Ok(flow_key) = key {
                    match map_data.get(&flow_key, 0) {
                        Ok(cur_throughput) => {

                            let mut total_throughput = 0;
                            for index in 1..nr_cpus {
                                total_throughput += cur_throughput[index];
                            }

                            add_to_heap(heap, top_n, &flow_key, total_throughput);
                        },
                        _ => {}
                    }

                    if let Err(_) = map_data.remove(&flow_key) {
                        eprintln!("Error removing data from map...");
                    }
                }
            }
        },
        None => { return; }
    }
}

// Attach to the beginning of the kernel function mentioned via kprobe_name.
fn attach_to_beginning(ebpf: &mut Ebpf, program_name: &str, kprobe_name: &str) -> anyhow::Result<()> {
    let program: &mut KProbe = ebpf.program_mut(program_name).unwrap().try_into()?;
    program.load()?;

    program.attach(kprobe_name, 0)?;

    Ok(())
}
