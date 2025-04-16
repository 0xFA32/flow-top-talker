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

#[cfg(feature = "with-aya")]
unsafe impl aya::Pod for FlowKey {}