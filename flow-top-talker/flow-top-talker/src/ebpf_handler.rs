use aya::{
    maps::{
        Array, HashMap, MapData, MapError, PerCpuHashMap
    }, programs::KProbe, util::nr_cpus, Ebpf
};
#[rustfmt::skip]
use log::{debug, warn};

use crate::{cli::Cli, flow_info::LimitedMaxHeap};

use flow_top_talker_common::common_types::{
    ConfigKey, FlowKey,
    CONFIG_MAP_NAME, EGRESS_TRACKER_0_MAP_NAME,
    EGRESS_TRACKER_1_MAP_NAME, FLAG_MAP_NAME, INGRESS_TRACKER_0_MAP_NAME,
    INGRESS_TRACKER_1_MAP_NAME,
};
use anyhow::anyhow;

/// Handler to ebpf.
pub struct EbpfHandler {
    ebpf: Ebpf,
    nr_cpus: usize,
}

impl EbpfHandler {
    /// Init the ebpf handler by loading by the ebpf program and determining number of ncpus
    /// which would be used later to capture the results.
    /// 
    /// Bump the memlock rlimit as recommended by aya.
    pub fn init() -> anyhow::Result<EbpfHandler> {
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
        
        Self::init_flag(&mut ebpf)?;

        let nr_cpus = nr_cpus();
        if nr_cpus.is_err() {
            return Err(anyhow!("Not able to get possible CPU. Exiting early.."));
        }
        
        Ok(EbpfHandler { ebpf, nr_cpus: nr_cpus.unwrap() })
    }

    /// Add config provided by the user to the ebpf program.
    pub fn add_config(
        &mut self,
        cli: &Cli
    ) -> anyhow::Result<()> {
        match self.ebpf.map_mut(CONFIG_MAP_NAME) {
            Some(map) => {
                let mut map_data: HashMap<&mut MapData, ConfigKey, u64> =
                    HashMap::try_from(map).unwrap();
                
                if let Some(pid) = cli.pid {
                    map_data.insert(ConfigKey::PID, pid, 0)?;
                }
    
                if let Some(tid) = cli.tid {
                    map_data.insert(ConfigKey::TID, tid, 0)?;
                }
    
                Ok(())
            },
            None => {
                Err(anyhow!("Failed to read config map name"))
            }
        }
    }

    /// Attach to required kprobes.
    pub fn attach(&mut self) -> anyhow::Result<()> {
        self.attach_to_beginning("tcp_sendmsg_kprobe", "tcp_sendmsg")?;
        self.attach_to_beginning("tcp_recvmsg_kprobe", "tcp_recvmsg")?;
        self.attach_to_beginning("udp_sendmsg_kprobe", "udp_sendmsg")?;
        self.attach_to_beginning("udp_recvmsg_kprobe", "udp_recvmsg")?;

        Ok(())
    }

    /// Rotate data and add it to the heap provided.
    /// 
    /// The flow info is shared between ebpf program and user app via a double buffer.
    pub fn rotate_data(
        &mut self,
        ingress_heap: &mut LimitedMaxHeap,
        cur_flag_value: u32,
        egress_heap: &mut LimitedMaxHeap,
    ) -> anyhow::Result<()> {
        if let Some(map) = self.ebpf.map_mut(FLAG_MAP_NAME) {
            let mut array: Array<&mut _, u32> = Array::try_from(map).unwrap();
            if cur_flag_value == 0 {
                let _ = array.set(0, 1, 0);
                self.fetch_latest_data(INGRESS_TRACKER_0_MAP_NAME, ingress_heap);
                self.fetch_latest_data(EGRESS_TRACKER_0_MAP_NAME, egress_heap);
            } else {
                let _ = array.set(0, 0, 0);
                self.fetch_latest_data(INGRESS_TRACKER_1_MAP_NAME, ingress_heap);
                self.fetch_latest_data(EGRESS_TRACKER_1_MAP_NAME, egress_heap);
            }
        }

        Ok(())
    }


    // Attach to the beginning of the kernel function mentioned via kprobe_name.
    fn attach_to_beginning(&mut self, program_name: &str, kprobe_name: &str) -> anyhow::Result<()> {
        let program: &mut KProbe = self.ebpf.program_mut(program_name).unwrap().try_into()?;
        program.load()?;

        program.attach(kprobe_name, 0)?;

        Ok(())
    }

    /// Fetch latest flow info data from the provided 
    fn fetch_latest_data(
        &mut self,
        map_name: &str, 
        heap: &mut LimitedMaxHeap,
    ) {
        if let Some(map) = self.ebpf.map_mut(map_name) {
            let mut map_data: PerCpuHashMap<&mut MapData, FlowKey, u64> =
                PerCpuHashMap::try_from(map).unwrap();
            let keys: Vec<Result<FlowKey, MapError>> = map_data.keys().collect();
            for key in keys.into_iter().flatten() {
                if let Ok(cur_throughput) = map_data.get(&key, 0) {
                    let mut total_throughput = 0;
                    for index in 0..self.nr_cpus {
                        total_throughput += cur_throughput[index];
                    }

                    heap.add(&key, total_throughput);
                }

                if map_data.remove(&key).is_err() {
                    eprintln!("Error removing data from map...");
                }
            }
        }
    }
    
    fn init_flag(ebpf: &mut Ebpf) -> anyhow::Result<()> {
        if let Some(map) = ebpf.map_mut(FLAG_MAP_NAME) {
            let mut array: Array<&mut _, u32> = Array::try_from(map).unwrap();
            array.set(0, 0, 0)?;

            let mut counter = 0usize;
            while counter < 5 {
                if array.get(&0, 0).unwrap() == 0 {
                    break;
                }

                counter += 1;
            }

            if counter == 5 {
                return Err(anyhow!("Failed to init flag value"));
            }
        }

        Ok(())
    }
}
