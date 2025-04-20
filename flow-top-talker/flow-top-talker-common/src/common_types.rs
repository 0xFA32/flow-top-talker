/// Common types used in both ebpf and user space application.

/// Set of map names.
pub static INGRESS_TRACKER_0_MAP_NAME: &str = "INGRESS_TRACKER_0";
pub static INGRESS_TRACKER_1_MAP_NAME: &str = "INGRESS_TRACKER_1";
pub static EGRESS_TRACKER_0_MAP_NAME: &str = "EGRESS_TRACKER_0";
pub static EGRESS_TRACKER_1_MAP_NAME: &str = "INGRESS_TRACKER_1";
pub static FLAG_MAP_NAME: &str = "FLAG";
pub static CONFIG_MAP_NAME: &str = "CONFIG";

pub static TCP: u8 = 0;
pub static UDP: u8 = 1;

/// Struct defining the key for each flow by 5-tuple.
/// 
/// Align the struct according to the cache line. Rust ensures remaining would be padded automatically.
/// For now setting it up for x86_64 and aarch64.
/// https://github.com/crossbeam-rs/crossbeam/blob/983d56b6007ca4c22b56a665a7785f40f55c2a53/crossbeam-utils/src/cache_padded.rs#L80-L88
#[repr(C)]
#[cfg_attr(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
), repr(align(128)))]
#[cfg_attr(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
)), repr(align(64)))]
#[repr(align(64))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_addr: u32,
    pub dest_addr: u32,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(
        src_addr: u32,
        dest_addr: u32,
        src_port: u16,
        dest_port: u16,
        protocol: u8,
    ) -> FlowKey {
        Self {
            src_addr,
            dest_addr,
            src_port,
            dest_port,
            protocol,
        }
    }
}

/// Key for the config to pass to ebpf program which can be used to filter out the data captured from ebpf.
/// 
/// This would take 1 byte as it is just 2 values for now and it is fine 
/// if it is not padded as the use case of this key is minimal,
///     1. Key is used to setup the initial configuration after which user space program
///        will not be updating it further.
///     2. Ebpf program uses it to filter out the data which if needed we can define a
///        PerCpu hash map for it. But considering only 2 values, keeping it simple for
///        now.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConfigKey {
    PID,
    TID,
}

/// Impl Pod for the keys used in ebpf HashMap.
#[cfg(feature = "with-aya")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "with-aya")]
unsafe impl aya::Pod for ConfigKey {}