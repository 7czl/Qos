#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::{LpmTrie, PerCpuHashMap},
    maps::lpm_trie::Key,
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use qos_common::{RateLimitConfig, TokenBucketState, TC_ACT_PIPE, TC_ACT_SHOT};

// ----- Ingress (download) maps: matched against the source IP of incoming packets -----

#[map]
static RULES_INGRESS: LpmTrie<u32, RateLimitConfig> = LpmTrie::with_max_entries(1024, 0);

#[map]
static TOKENS_INGRESS: PerCpuHashMap<u32, TokenBucketState> =
    PerCpuHashMap::with_max_entries(1024, 0);

// ----- Egress (upload) maps: matched against the destination IP of outgoing packets -----

#[map]
static RULES_EGRESS: LpmTrie<u32, RateLimitConfig> = LpmTrie::with_max_entries(1024, 0);

#[map]
static TOKENS_EGRESS: PerCpuHashMap<u32, TokenBucketState> =
    PerCpuHashMap::with_max_entries(1024, 0);

// ----- Classifiers -----

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match try_ingress(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE, // On error, default to allowing the packet
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_egress(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE, // On error, default to allowing the packet
    }
}

// ----- Implementation -----

/// Parse Ethernet + IPv4 headers and return (src_addr, dst_addr, packet_len)
/// in host-meaningful form. Both addresses are kept in network byte order
/// (big-endian) — that's what we use as the LPM trie key.
#[inline(always)]
fn parse_ipv4(ctx: &TcContext) -> Result<Option<(u32, u32, u64)>, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    // Copy the field out of the packed struct via a block expression to avoid
    // a misaligned reference.
    let ether_type = { ethhdr.ether_type };
    if ether_type != EtherType::Ipv4 {
        return Ok(None);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let src_addr = { ipv4hdr.src_addr };
    let dst_addr = { ipv4hdr.dst_addr };
    let tot_len = { ipv4hdr.tot_len };
    let packet_len = u16::from_be(tot_len) as u64;

    Ok(Some((src_addr, dst_addr, packet_len)))
}

#[inline(always)]
fn try_ingress(ctx: &TcContext) -> Result<i32, ()> {
    let (src_addr, _dst_addr, packet_len) = match parse_ipv4(ctx)? {
        Some(t) => t,
        None => return Ok(TC_ACT_PIPE),
    };

    // Look up the source IP (incoming traffic = "download from this peer").
    let lpm_key = Key::new(32, src_addr);
    let config = match RULES_INGRESS.get(&lpm_key) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_PIPE), // No rule — allow
    };

    let now_ns = unsafe { bpf_ktime_get_ns() };

    match TOKENS_INGRESS.get_ptr_mut(&src_addr) {
        Some(ptr) => {
            let state = unsafe { &mut *ptr };
            if state.process_packet(config, packet_len, now_ns) {
                Ok(TC_ACT_PIPE)
            } else {
                Ok(TC_ACT_SHOT)
            }
        }
        None => {
            let mut new_state = TokenBucketState {
                tokens: config.burst,
                last_refill_ns: now_ns,
            };
            let allowed = new_state.process_packet(config, packet_len, now_ns);
            let _ = TOKENS_INGRESS.insert(&src_addr, &new_state, 0);
            if allowed { Ok(TC_ACT_PIPE) } else { Ok(TC_ACT_SHOT) }
        }
    }
}

#[inline(always)]
fn try_egress(ctx: &TcContext) -> Result<i32, ()> {
    let (_src_addr, dst_addr, packet_len) = match parse_ipv4(ctx)? {
        Some(t) => t,
        None => return Ok(TC_ACT_PIPE),
    };

    // Look up the destination IP (outgoing traffic = "upload to this peer").
    let lpm_key = Key::new(32, dst_addr);
    let config = match RULES_EGRESS.get(&lpm_key) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_PIPE), // No rule — allow
    };

    let now_ns = unsafe { bpf_ktime_get_ns() };

    match TOKENS_EGRESS.get_ptr_mut(&dst_addr) {
        Some(ptr) => {
            let state = unsafe { &mut *ptr };
            if state.process_packet(config, packet_len, now_ns) {
                Ok(TC_ACT_PIPE)
            } else {
                Ok(TC_ACT_SHOT)
            }
        }
        None => {
            let mut new_state = TokenBucketState {
                tokens: config.burst,
                last_refill_ns: now_ns,
            };
            let allowed = new_state.process_packet(config, packet_len, now_ns);
            let _ = TOKENS_EGRESS.insert(&dst_addr, &new_state, 0);
            if allowed { Ok(TC_ACT_PIPE) } else { Ok(TC_ACT_SHOT) }
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
