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
    programs::ProbeContext,
    maps::{Array, HashMap}
};

use bindings::*;
use flow_top_talker_common::common_types::FlowKey;

// IpV4 and IpV6.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Maintain 2 sets of maps to track the current throughput for ingress and egress.
/// 
/// Based on the flag value set choose the appropriate map. This is an easy to way to clear
/// the map by the user program while the ebpf program continues to track the throughput.
/// 
/// TODO: use per-cpu hash map and aggregate in user-space.
#[map(name = "INGRESS_TRACKER_0")]
static INGRESS_TRACKER_0: HashMap<FlowKey, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "INGRESS_TRACKER_1")]
static INGRESS_TRACKER_1: HashMap<FlowKey, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "EGRESS_TRACKER_0")]
static EGRESS_TRACKER_0: HashMap<FlowKey, u64> = HashMap::with_max_entries(10240, 0);

#[map(name = "EGRESS_TRACKER_1")]
static EGRESS_TRACKER_1: HashMap<FlowKey, u64> = HashMap::with_max_entries(10240, 0);

// Flag use to reset between the 2 tracker.
#[map(name = "FLAG")]
static FLAG: Array<u32> = Array::with_max_entries(1, 0);

#[kprobe]
pub fn tcp_sendmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    if let Some((flow_key, size)) = unwrap_flow_info(&ctx, 0) {
        let flag_ptr = FLAG.get_ptr_mut(0).ok_or(1u32)?;
        let flag = unsafe { core::ptr::read_volatile(flag_ptr) };

        let tracker = if flag == 0 {
            &EGRESS_TRACKER_0
        } else {
            &EGRESS_TRACKER_1
        };

        match tracker.get_ptr_mut(&flow_key) {
            Some(val) => unsafe {
                *val += size as u64;
            },
            None => {
                let _ = tracker.insert(&flow_key, &(size as u64), 0);
            }
        };
    }

    Ok(0)
}

#[kprobe]
pub fn tcp_recvmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_tcp_recvmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_recvmsg_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    if let Some((flow_key, size)) = unwrap_flow_info(&ctx, 0) {
        let flag_ptr = FLAG.get_ptr_mut(0).ok_or(1u32)?;
        let flag = unsafe { core::ptr::read_volatile(flag_ptr) };

        let tracker = if flag == 0 {
            &INGRESS_TRACKER_0
        } else {
            &INGRESS_TRACKER_1
        };

        match tracker.get_ptr_mut(&flow_key) {
            Some(val) => unsafe {
                *val += size as u64;
            },
            None => {
                let _ = tracker.insert(&flow_key, &(size as u64), 0);
            }
        };
    }

    Ok(0)
}

#[kprobe]
pub fn udp_sendmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_udp_sendmsg_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    if let Some((flow_key, size)) = unwrap_flow_info(&ctx, 1) {
        let flag_ptr = FLAG.get_ptr_mut(0).ok_or(1u32)?;
        let flag = unsafe { core::ptr::read_volatile(flag_ptr) };

        let tracker = if flag == 0 {
            &EGRESS_TRACKER_0
        } else {
            &EGRESS_TRACKER_1
        };

        match tracker.get_ptr_mut(&flow_key) {
            Some(val) => unsafe {
                *val += size as u64;
            },
            None => {
                let _ = tracker.insert(&flow_key, &(size as u64), 0);
            }
        };
    }

    Ok(0)
}

#[kprobe]
pub fn udp_recvmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_udp_recvmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_udp_recvmsg_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    if let Some((flow_key, size)) = unwrap_flow_info(&ctx, 1) {
        let flag_ptr = FLAG.get_ptr_mut(0).ok_or(1u32)?;
        let flag = unsafe { core::ptr::read_volatile(flag_ptr) };

        let tracker = if flag == 0 {
            &INGRESS_TRACKER_0
        } else {
            &INGRESS_TRACKER_1
        };

        match tracker.get_ptr_mut(&flow_key) {
            Some(val) => unsafe {
                *val += size as u64;
            },
            None => {
                let _ = tracker.insert(&flow_key, &(size as u64), 0);
            }
        };
    }

    Ok(0)
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
    let pid_tgid = bpf_get_current_pid_tgid();

    match sk_common.skc_family {
        AF_INET6 => {
            // Skipping handling Ipv6 traffic for now. 
            return None;
        },
        AF_INET => {

            // Network stores in big endian. Not sure which values in kernel are defined as
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
