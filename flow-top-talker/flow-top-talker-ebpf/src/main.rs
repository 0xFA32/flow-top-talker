#![no_std]
#![no_main]

// Allow following cases for bindings.
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

mod bindings;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::{Array, HashMap, PerCpuHashMap},
    programs::ProbeContext,
};

use bindings::*;
use flow_top_talker_common::common_types::{ConfigKey, FlowKey, TCP, UDP};

// IpV4 and IpV6.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Maintain 2 sets of maps to track the current throughput for ingress and egress.
/// 
/// Based on the flag value choose the appropriate map. This is an easy to way to clear
/// the map by the user program while the ebpf program continues to track the throughput.
/// 
#[map(name = "INGRESS_TRACKER_0")]
static INGRESS_TRACKER_0: PerCpuHashMap<FlowKey, u64> = PerCpuHashMap::with_max_entries(10240, 0);

#[map(name = "INGRESS_TRACKER_1")]
static INGRESS_TRACKER_1: PerCpuHashMap<FlowKey, u64> = PerCpuHashMap::with_max_entries(10240, 0);

#[map(name = "EGRESS_TRACKER_0")]
static EGRESS_TRACKER_0: PerCpuHashMap<FlowKey, u64> = PerCpuHashMap::with_max_entries(10240, 0);

#[map(name = "EGRESS_TRACKER_1")]
static EGRESS_TRACKER_1: PerCpuHashMap<FlowKey, u64> = PerCpuHashMap::with_max_entries(10240, 0);

// Flag use to reset between the 2 tracker.
#[map(name = "FLAG")]
static FLAG: Array<u32> = Array::with_max_entries(1, 0);

// HashMap used to maintain config provided by the user.
#[map(name = "CONFIG")]
static CONFIG: HashMap<ConfigKey, u64> = HashMap::with_max_entries(2, 0);

macro_rules! process_kprobe_func {
    ($fn_name:ident, $tracker0:expr, $tracker1:expr, $prot:expr) => {
        fn $fn_name(ctx: ProbeContext) -> Result<u32, u32> {
            if let Some((flow_key, size)) = unwrap_flow_info(&ctx, $prot) {
                let flag_ptr = FLAG.get_ptr_mut(0).ok_or(1u32)?;
                let flag = unsafe { core::ptr::read_volatile(flag_ptr) };
    
                let tracker = if flag == 0 {
                    &$tracker0
                } else {
                    &$tracker1
                };
    
                match tracker.get_ptr_mut(&flow_key) {
                    Some(val) => {
                        unsafe { *val += size as u64; }
                    },
                    None => {
                        let _ = tracker.insert(&flow_key, &(size as u64), 0);
                    }
                }
            }
    
            return Ok(0);
        }
    };
}

process_kprobe_func!(try_tcp_sendmsg_kprobe, EGRESS_TRACKER_0, EGRESS_TRACKER_1, TCP);
process_kprobe_func!(try_tcp_recvmsg_kprobe, INGRESS_TRACKER_0, INGRESS_TRACKER_1, TCP);
process_kprobe_func!(try_udp_sendmsg_kprobe, EGRESS_TRACKER_0, EGRESS_TRACKER_1, UDP);
process_kprobe_func!(try_udp_recvmsg_kprobe, INGRESS_TRACKER_0, INGRESS_TRACKER_1, UDP);

#[kprobe]
pub fn tcp_sendmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn tcp_recvmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_tcp_recvmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn udp_sendmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn udp_recvmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_udp_recvmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Unwrap flow info from TCP/UDP send and recv msg. In all of the APIs the 3rd parameter
/// denotes the size.
/// 
/// tcp_sendmsg: https://github.com/torvalds/linux/blob/1a1d569a75f3ab2923cb62daf356d102e4df2b86/net/ipv4/tcp.c#L1361
/// tcp_recvmsg: https://github.com/torvalds/linux/blob/1a1d569a75f3ab2923cb62daf356d102e4df2b86/net/ipv4/tcp.c#L2863
/// 
/// udp_sendmsg: https://github.com/torvalds/linux/blob/1a1d569a75f3ab2923cb62daf356d102e4df2b86/net/ipv4/udp.c#L1270
/// udp_recvmsg: https://github.com/torvalds/linux/blob/1a1d569a75f3ab2923cb62daf356d102e4df2b86/net/ipv4/udp.c#L2025
fn unwrap_flow_info(ctx: &ProbeContext, prot: u8) -> Option<(FlowKey, usize)> {
    let sock: *mut sock = ctx.arg(0)?;
    let len: usize = ctx.arg(2)?;
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common).ok()?
    };


    if let Some(pid) = CONFIG.get_ptr(&ConfigKey::PID) {
        unsafe {
            if *pid as u32 != bpf_get_current_pid_tgid() as u32 {
                return None;
            }
        }
    }

    if let Some(tid) = CONFIG.get_ptr(&ConfigKey::TID) {
        unsafe {
            if *tid as u32 != (bpf_get_current_pid_tgid() >> 32) as u32 {
                return None;
            }
        }
    }

    match sk_common.skc_family {
        AF_INET6 => {
            // Skipping handling Ipv6 traffic for now. 
            return None;
        },
        AF_INET => {

            // Network stores in big endian. Not sure if the values in kernel are defined as
            // big endian or native endian. So converting all of them as it would be no-op 
            // if it is already big endian.
            let src_addr = u32::from_be(unsafe {
                sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
            });

            let dest_addr = u32::from_be(unsafe {
                sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
            });

            let src_port = u16::from_be(unsafe {
                sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num
            });

            let dest_port = u16::from_be(unsafe {
                sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport
            });

            let flow_key = FlowKey::new(src_addr, dest_addr, src_port, dest_port, prot);
            return Some((flow_key, len));
        },
        _ => {
            return None;
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
