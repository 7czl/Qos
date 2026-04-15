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

/// LPM Trie storing rate-limit rules keyed by IPv4 address (network byte order).
/// The aya-ebpf `Key<u32>` wraps the u32 with a prefix_len field, giving us
/// the standard BPF LPM trie key layout: { prefix_len: u32, addr: u32 }.
#[map]
static RULES: LpmTrie<u32, RateLimitConfig> = LpmTrie::with_max_entries(1024, 0);

/// Per-CPU hash map storing token bucket state keyed by the raw u32 IP address.
/// Per-CPU avoids lock contention across cores.
#[map]
static TOKEN_STATES: PerCpuHashMap<u32, TokenBucketState> =
    PerCpuHashMap::with_max_entries(1024, 0);

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE, // On error, default to allowing the packet
    }
}

#[inline(always)]
fn try_tc_ingress(ctx: &TcContext) -> Result<i32, ()> {
    // Parse Ethernet header
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    // Only process IPv4 packets; pass everything else through.
    // Use block expression `{ ... }` to copy the field value out of the packed
    // struct, avoiding a misaligned reference (EthHdr is #[repr(C, packed)]).
    let ether_type = { ethhdr.ether_type };
    if ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    // Parse IPv4 header (also packed — copy fields via block expressions)
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    // Source IP in network byte order (big-endian) — used as-is for LPM lookup
    let src_addr = { ipv4hdr.src_addr };

    // Total packet length from IP header (network byte order -> host)
    let tot_len = { ipv4hdr.tot_len };
    let packet_len = u16::from_be(tot_len) as u64;

    // Look up the source IP in the LPM Trie with a /32 prefix (exact match).
    // The trie will return the longest matching prefix rule.
    let lpm_key = Key::new(32, src_addr);
    let config = match RULES.get(&lpm_key) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_PIPE), // No matching rule — allow
    };

    // Get current time for token bucket calculations
    let now_ns = unsafe { bpf_ktime_get_ns() };

    // Look up or initialize the per-CPU token bucket state for this IP
    let state_ptr = TOKEN_STATES.get_ptr_mut(&src_addr);
    match state_ptr {
        Some(ptr) => {
            // State exists — update in place
            let state = unsafe { &mut *ptr };
            if state.process_packet(config, packet_len, now_ns) {
                Ok(TC_ACT_PIPE)
            } else {
                Ok(TC_ACT_SHOT)
            }
        }
        None => {
            // No state yet — initialize a new token bucket
            let mut new_state = TokenBucketState {
                tokens: config.burst,
                last_refill_ns: now_ns,
            };
            let allowed = new_state.process_packet(config, packet_len, now_ns);
            // Insert the new state into the map (BPF_ANY = 0)
            let _ = TOKEN_STATES.insert(&src_addr, &new_state, 0);
            if allowed {
                Ok(TC_ACT_PIPE)
            } else {
                Ok(TC_ACT_SHOT)
            }
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
