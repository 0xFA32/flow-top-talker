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
/// TODO: Add padding to make it cache friendly.

#[repr(C)]
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

/// Key for the config to pass to ebpf program.
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