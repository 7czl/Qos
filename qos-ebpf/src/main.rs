#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
    macros::{classifier, map},
    maps::lpm_trie::Key,
    maps::{HashMap, LpmTrie},
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
// `bpf_spin_lock` here refers to the *type* re-exported by qos-common; the
// function symbol of the same name imported from `aya_ebpf::helpers` lives in
// the value namespace, so the two coexist without a conflict.
use qos_common::{
    bpf_spin_lock as BpfSpinLock, RateLimitConfig, TokenBucketState, TC_ACT_PIPE, TC_ACT_SHOT,
};

/// One second in nanoseconds. Mirrors `qos_common::NANOS_PER_SEC` so the
/// inlined refill arithmetic inside the spin-locked critical section stays
/// independent of any function calls into other crates.
const NANOS_PER_SEC: u64 = 1_000_000_000;

// ----- Ingress (download) maps: matched against the source IP of incoming packets -----

#[map]
static RULES_INGRESS: LpmTrie<u32, RateLimitConfig> = LpmTrie::with_max_entries(1024, 0);

/// Shared (cross-CPU) token bucket state for the ingress data path.
///
/// `BPF_MAP_TYPE_HASH` (one entry shared across all CPUs) replaces the
/// previous `BPF_MAP_TYPE_PERCPU_HASH`; concurrent updates are serialized by
/// the `bpf_spin_lock` field embedded inside each `TokenBucketState` value.
#[map]
static TOKENS_INGRESS: HashMap<u32, TokenBucketState> = HashMap::with_max_entries(1024, 0);

// ----- Egress (upload) maps: matched against the destination IP of outgoing packets -----

#[map]
static RULES_EGRESS: LpmTrie<u32, RateLimitConfig> = LpmTrie::with_max_entries(1024, 0);

/// Shared (cross-CPU) token bucket state for the egress data path.
/// See `TOKENS_INGRESS` for the rationale of the type switch.
#[map]
static TOKENS_EGRESS: HashMap<u32, TokenBucketState> = HashMap::with_max_entries(1024, 0);

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

/// Shared read–modify–write helper for one matched IPv4 entry.
///
/// Implements the locked path described in
/// `.kiro/specs/ebpf-rate-limiter-spinlock-accuracy/design.md`:
///
/// 1. Sample `bpf_ktime_get_ns()` strictly *outside* the lock — helpers are
///    forbidden inside a `bpf_spin_lock` critical section.
/// 2. If the entry doesn't yet exist (first packet for this IP),
///    optimistically `insert` an initial `{ lock: 0, tokens: burst,
///    last_refill_ns: now }` value. Both `get_ptr` and `insert` are helpers
///    and therefore must run outside the lock. Concurrent inserts from other
///    CPUs are benign: each writes ~equivalent state.
/// 3. Re-`get_ptr_mut` to obtain a mutable pointer. If the entry is still
///    missing (e.g. `ENOSPC` at insert time), fail open with `TC_ACT_PIPE`
///    rather than holding traffic.
/// 4. Inside the lock, run the refill arithmetic *inlined* (no method calls,
///    no helper calls, no BPF-to-BPF calls) using a split-multiplication
///    equivalent to `qos_common::TokenBucketState::refill_tokens`, then take
///    the allow / drop decision and write back `tokens` and `last_refill_ns`.
/// 5. Release the lock at a single unlock site that all branches converge to,
///    then map the `allowed` boolean to `TC_ACT_PIPE` / `TC_ACT_SHOT`.
///
/// Called by both `try_ingress` and `try_egress` after a successful LPM
/// lookup to perform the shared, lock-protected token bucket update.
#[inline(always)]
fn try_one(
    map: &HashMap<u32, TokenBucketState>,
    ip: u32,
    config: &RateLimitConfig,
    packet_len: u64,
) -> Result<i32, ()> {
    // 1) Sample time strictly *outside* the lock. Helpers are forbidden once
    //    we hold `bpf_spin_lock`.
    let now_ns = unsafe { bpf_ktime_get_ns() };

    // 2) First-packet path: `get_ptr` + optimistic `insert`. Both are helpers
    //    and therefore must run outside the lock. Concurrent inserts from
    //    other CPUs racing on the same key are benign — they each write
    //    `{ tokens = burst, last_refill_ns ≈ now }`, so any winner produces
    //    state that is ~equivalent up to a few microseconds of clock skew
    //    (well below the ±2% accuracy budget).
    if map.get_ptr(&ip).is_none() {
        let init = TokenBucketState {
            lock: BpfSpinLock { val: 0 },
            tokens: config.burst,
            last_refill_ns: now_ns,
        };
        // BPF_ANY (= 0): overwrite-or-insert. Errors are non-fatal — we'll
        // fall through to the fail-open branch below if the second lookup
        // still misses.
        let _ = map.insert(&ip, &init, 0);
    }

    // 3) Re-lookup to obtain a mutable pointer. If even now the entry is
    //    missing (e.g. `insert` hit `ENOSPC`), fail open with `TC_ACT_PIPE`
    //    rather than holding the lock or dropping traffic. This matches the
    //    fail-open posture used elsewhere in the data path on errors.
    let ptr = match map.get_ptr_mut(&ip) {
        Some(p) => p,
        None => return Ok(TC_ACT_PIPE),
    };
    // Safety: the verifier guarantees that the pointer returned by
    // `bpf_map_lookup_elem` for a present key is valid for the duration of
    // the program. We hold no other reference to the value while we
    // dereference it.
    let state = unsafe { &mut *ptr };

    // 4) Critical section — pure ALU plus field reads/writes only. No method
    //    calls, no BPF-to-BPF calls, no helper calls. Branches converge on a
    //    single `bpf_spin_unlock` site (immediately before the closing brace
    //    of this `unsafe` block).
    let allowed: bool;
    unsafe {
        // Acquire — return value is the kernel `c_long`; ignored intentionally.
        bpf_spin_lock(&mut state.lock as *mut _);

        // ---- inlined refill (mirrors qos_common::TokenBucketState::refill_tokens) ----
        // Guard against time going backwards (clock skew or stale entry):
        // saturating subtraction expressed as a branch so we never emit a
        // libcall like `__satsubdi3` from inside the locked region.
        let elapsed_ns = if now_ns >= state.last_refill_ns {
            now_ns - state.last_refill_ns
        } else {
            0
        };

        // Split the multiplication `elapsed_ns * rate` into full-second and
        // sub-second components to keep every intermediate value within u64,
        // matching the reference implementation in qos-common.
        let elapsed_secs = elapsed_ns / NANOS_PER_SEC;
        let remaining_ns = elapsed_ns % NANOS_PER_SEC;
        let rate = config.rate;

        // Tokens accumulated from full elapsed seconds.
        // `saturating_mul` would lower to `__multi3` (128-bit) on some
        // targets, which BPF does not support. We instead cap the operand
        // so the product cannot overflow u64; the burst clamp below makes
        // any over-saturation irrelevant.
        let tokens_from_secs = if rate == 0 {
            0
        } else if elapsed_secs > u64::MAX / rate {
            u64::MAX
        } else {
            elapsed_secs.wrapping_mul(rate)
        };

        // Tokens accumulated from the remaining sub-second fraction.
        // `remaining_ns < 1e9`, so the product can only overflow when
        // `rate > ~1.8e10`. The same overflow guard pattern is used.
        let tokens_from_frac = if rate == 0 {
            0
        } else if remaining_ns > u64::MAX / rate {
            u64::MAX / NANOS_PER_SEC
        } else {
            remaining_ns.wrapping_mul(rate) / NANOS_PER_SEC
        };

        // Sum new tokens with overflow guard (no `saturating_add` to avoid
        // any chance of a 128-bit lowering on this target).
        let (new_tokens_sum, ov_sum) = tokens_from_secs.overflowing_add(tokens_from_frac);
        let new_tokens = if ov_sum { u64::MAX } else { new_tokens_sum };

        let (refilled, ov_refill) = state.tokens.overflowing_add(new_tokens);
        let refilled = if ov_refill { u64::MAX } else { refilled };

        // Cap at burst.
        let capped = if refilled > config.burst {
            config.burst
        } else {
            refilled
        };

        // ---- inlined spend / decision ----
        if capped >= packet_len {
            state.tokens = capped - packet_len;
            allowed = true;
        } else {
            state.tokens = capped;
            allowed = false;
        }
        state.last_refill_ns = now_ns;

        // Single unlock site — every branch above converges here before we
        // leave the locked region.
        bpf_spin_unlock(&mut state.lock as *mut _);
    }

    // 5) Map the boolean back to a TC action *outside* the lock.
    if allowed {
        Ok(TC_ACT_PIPE)
    } else {
        Ok(TC_ACT_SHOT)
    }
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
        None => return Ok(TC_ACT_PIPE), // No rule — allow; TOKENS_INGRESS untouched.
    };

    // Delegate to the shared locked RMW helper.
    try_one(&TOKENS_INGRESS, src_addr, config, packet_len)
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
        None => return Ok(TC_ACT_PIPE), // No rule — allow; TOKENS_EGRESS untouched.
    };

    // Delegate to the shared locked RMW helper.
    try_one(&TOKENS_EGRESS, dst_addr, config, packet_len)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
