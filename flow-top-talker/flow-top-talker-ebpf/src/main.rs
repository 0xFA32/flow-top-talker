#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn tcp_sendmsg_kprobe(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "tcp_sendmsg kprobe called");
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
    info!(&ctx, "tcp_recvmsg kprobe called");
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
    info!(&ctx, "udp_sendmsg kprobe called");
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
    info!(&ctx, "udp_recvmsg kprobe called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
