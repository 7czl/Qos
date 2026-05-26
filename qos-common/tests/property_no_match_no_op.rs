// Feature: ebpf-rate-limiter-spinlock-accuracy, Property B: 无匹配规则的包不修改 Shared_Token_Map
//
// **Validates: Requirements 3.3**
//
// For any LPM rule set R and any IPv4 address `ip` not covered by any prefix
// in R, calling the userspace decision model once with `ip` must:
//   (a) return `TC_ACT_PIPE`, and
//   (b) leave the `tokens` map (the userspace stand-in for `TOKENS_INGRESS` /
//       `TOKENS_EGRESS`) byte-equal to its pre-call state — both the key set
//       and every entry's `tokens` / `last_refill_ns` fields.
//
// The model `try_decision_model` is behaviorally isomorphic with the eBPF
// data path's `try_one`: it performs the LPM lookup outside the (modeled)
// lock, returns `TC_ACT_PIPE` immediately on miss without touching `tokens`,
// and only on a hit does it run the optimistic insert + locked RMW. Property
// B exercises only the miss branch (the IP generator is filtered to miss),
// so the hit branch is kept for isomorphism but verified separately by
// Property A.

use std::collections::HashMap;

use proptest::prelude::*;
use qos_common::{bpf_spin_lock, RateLimitConfig, TokenBucketState, TC_ACT_PIPE, TC_ACT_SHOT};

/// Zero-initialized `bpf_spin_lock` used to populate the `lock` field of
/// userspace `TokenBucketState` fixtures. The model never inspects this
/// field — concurrency is modeled by single-threaded execution — and the
/// byte-equality check explicitly compares only `(tokens, last_refill_ns)`.
const ZERO_LOCK: bpf_spin_lock = bpf_spin_lock { val: 0 };

// -------------------------------------------------------------------------
// LPM trie model
// -------------------------------------------------------------------------

/// A single CIDR rule. `addr` is stored in **host byte order** (so
/// 192.168.1.0 = 0xC0A80100); the test never crosses a kernel boundary so
/// the network-byte-order convention used by the real eBPF maps is
/// irrelevant here. Prefix masking treats `prefix_len` as the count of
/// most-significant bits to compare.
#[derive(Debug, Clone, Copy)]
struct LpmRule {
    prefix_len: u32,
    addr: u32,
    config: RateLimitConfig,
}

#[derive(Debug, Clone)]
struct LpmTrieModel {
    rules: Vec<LpmRule>,
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Ingress,
    Egress,
}

fn prefix_mask(prefix_len: u32) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

impl LpmTrieModel {
    fn new(rules: Vec<LpmRule>) -> Self {
        Self { rules }
    }

    /// Longest-prefix-match lookup. Returns the matching rule's config if any
    /// prefix in the set covers `ip`; `None` otherwise.
    fn lookup(&self, ip: u32) -> Option<RateLimitConfig> {
        let mut best: Option<&LpmRule> = None;
        for rule in &self.rules {
            let mask = prefix_mask(rule.prefix_len);
            if (ip & mask) == (rule.addr & mask) {
                match best {
                    None => best = Some(rule),
                    Some(b) if rule.prefix_len > b.prefix_len => best = Some(rule),
                    _ => {}
                }
            }
        }
        best.map(|r| r.config)
    }

    fn covers(&self, ip: u32) -> bool {
        self.lookup(ip).is_some()
    }
}

// -------------------------------------------------------------------------
// Userspace model of `try_one`
// -------------------------------------------------------------------------

/// Userspace stand-in for the eBPF `try_one` decision path. Behaviorally
/// isomorphic with the kernel implementation:
///
/// 1. LPM lookup against `rules`. On miss, return `TC_ACT_PIPE` immediately
///    **without reading or writing `tokens`** (Requirement 3.3).
/// 2. On hit, optimistically insert a fresh `{lock: 0, tokens: burst,
///    last_refill_ns: now}` if no entry exists, then run refill + spend +
///    writeback under the (here, single-threaded) modeled lock.
///
/// Property B exercises only the miss branch — the IP generator filters out
/// any address covered by `rules` — so the hit branch never runs in this
/// test. The branch is kept here so the model genuinely matches `try_one`.
fn try_decision_model(
    direction: Direction,
    rules: &LpmTrieModel,
    tokens: &mut HashMap<u32, TokenBucketState>,
    ip: u32,
    packet_len: u64,
) -> i32 {
    // `direction` mirrors the two TC programs (`tc_ingress` / `tc_egress`).
    // Both share identical no-match semantics, so the parameter is purely
    // structural here; we still exercise both values via the test generator.
    let _ = direction;

    let config = match rules.lookup(ip) {
        Some(cfg) => cfg,
        None => return TC_ACT_PIPE, // miss — leave `tokens` untouched
    };

    // Hit branch (not reached under Property B). Use a fixed clock value
    // because Property B never observes its effects; Property A covers the
    // refill / spend correctness with a real simulated clock.
    let now_ns = 0u64;
    let entry = tokens.entry(ip).or_insert(TokenBucketState {
        lock: ZERO_LOCK,
        tokens: config.burst,
        last_refill_ns: now_ns,
    });
    if entry.process_packet(&config, packet_len, now_ns) {
        TC_ACT_PIPE
    } else {
        TC_ACT_SHOT
    }
}

// -------------------------------------------------------------------------
// Snapshot helper for byte-equality comparison
// -------------------------------------------------------------------------

/// Stable, order-independent snapshot of the tokens map's externally-
/// observable state: key, `tokens`, and `last_refill_ns`. The `lock` field
/// is intentionally excluded — it is a `u32` with no semantic value at the
/// userspace boundary, and the kernel verifier forbids direct loads on it
/// anyway.
fn snapshot(tokens: &HashMap<u32, TokenBucketState>) -> Vec<(u32, u64, u64)> {
    let mut v: Vec<(u32, u64, u64)> = tokens
        .iter()
        .map(|(k, s)| (*k, s.tokens, s.last_refill_ns))
        .collect();
    v.sort_unstable_by_key(|x| x.0);
    v
}

// -------------------------------------------------------------------------
// Generators
// -------------------------------------------------------------------------

/// Generate a single LPM rule.
///
/// `prefix_len` is bounded to `[8, 32]` so that even the broadest rule
/// covers at most 1/256 of the IPv4 address space. With up to 16 rules in
/// a set, the joint coverage stays under ~6%, keeping the downstream
/// `prop_filter` highly productive (proptest discards <10% of generated
/// `(rules, ip)` pairs in practice).
fn rule_strategy() -> impl Strategy<Value = LpmRule> {
    (
        8u32..=32u32,
        any::<u32>(),
        1u64..=10_000_000_000u64,
        1u64..=10_000_000_000u64,
    )
        .prop_map(|(prefix_len, addr, rate, burst)| LpmRule {
            prefix_len,
            addr,
            config: RateLimitConfig { rate, burst },
        })
}

fn rules_strategy() -> impl Strategy<Value = LpmTrieModel> {
    proptest::collection::vec(rule_strategy(), 1..16).prop_map(LpmTrieModel::new)
}

/// Generate a `(rules, ip)` pair where `ip` is guaranteed not to be covered
/// by `rules`. Implemented as `prop_filter` over the joint space, exactly
/// as the design document specifies.
fn rules_and_unmatched_ip_strategy() -> impl Strategy<Value = (LpmTrieModel, u32)> {
    (rules_strategy(), any::<u32>()).prop_filter(
        "ip must not be covered by any rule in the LPM trie model",
        |(rules, ip)| !rules.covers(*ip),
    )
}

/// Pre-existing entry in the tokens map. Property B verifies that these
/// entries are not perturbed by a no-match call; their values are otherwise
/// irrelevant.
fn token_entry_strategy() -> impl Strategy<Value = (u32, TokenBucketState)> {
    (any::<u32>(), any::<u64>(), any::<u64>()).prop_map(|(k, t, l)| {
        (
            k,
            TokenBucketState {
                lock: ZERO_LOCK,
                tokens: t,
                last_refill_ns: l,
            },
        )
    })
}

fn tokens_strategy() -> impl Strategy<Value = HashMap<u32, TokenBucketState>> {
    proptest::collection::vec(token_entry_strategy(), 0..16).prop_map(|v| v.into_iter().collect())
}

fn direction_strategy() -> impl Strategy<Value = Direction> {
    prop_oneof![Just(Direction::Ingress), Just(Direction::Egress)]
}

// -------------------------------------------------------------------------
// Property B
// -------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property B: a packet whose IP is not covered by any LPM rule must
    /// (a) be returned with `TC_ACT_PIPE` and (b) leave the Shared_Token_Map
    /// byte-equal to its pre-call state, in both the ingress and egress
    /// directions.
    ///
    /// **Validates: Requirements 3.3**
    #[test]
    fn property_no_match_leaves_token_map_unchanged(
        (rules, ip) in rules_and_unmatched_ip_strategy(),
        mut tokens in tokens_strategy(),
        packet_len in 1u64..=65535u64,
        direction in direction_strategy(),
    ) {
        // Defensive guard: the strategy already filters out matching IPs,
        // but cross-check the precondition explicitly so a regression in
        // the filter would surface as a clear test failure rather than a
        // silently weakened property.
        prop_assert!(
            !rules.covers(ip),
            "test setup invariant violated: ip {:#010x} is covered by rules {:?}",
            ip,
            rules,
        );

        let before = snapshot(&tokens);

        let action = try_decision_model(direction, &rules, &mut tokens, ip, packet_len);

        // (a) Returned action is TC_ACT_PIPE (not TC_ACT_SHOT, not anything else).
        prop_assert_eq!(
            action,
            TC_ACT_PIPE,
            "expected TC_ACT_PIPE on no-match, got {} (TC_ACT_SHOT={})",
            action,
            TC_ACT_SHOT,
        );

        // (b) tokens map is byte-equal (key set + each entry's tokens /
        // last_refill_ns) to its pre-call snapshot.
        let after = snapshot(&tokens);
        prop_assert_eq!(
            &after,
            &before,
            "tokens map was modified by a no-match call: ip={:#010x}, packet_len={}, rules={:?}",
            ip,
            packet_len,
            rules,
        );
    }
}
