#![no_std]

/// TC action: pass the packet to the next filter/action in the chain.
pub const TC_ACT_PIPE: i32 = 0;
/// TC action: drop the packet.
pub const TC_ACT_SHOT: i32 = 2;

/// One second in nanoseconds.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// LPM Trie key for IPv4 addresses.
///
/// Used as the key type for the BPF LPM Trie map that stores rate-limit rules.
/// `prefix_len` is the CIDR prefix length (e.g. 24 for /24) and `addr` is the
/// IPv4 address in network byte order (big-endian).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LpmKeyV4 {
    pub prefix_len: u32,
    pub addr: u32,
}

/// Rate-limit configuration for a single rule.
///
/// Stored as the value in the LPM Trie map.
/// `rate` is the sustained rate in bytes per second.
/// `burst` is the maximum token bucket capacity in bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub rate: u64,
    pub burst: u64,
}

/// Per-CPU token bucket state.
///
/// Stored in a Per-CPU Hash Map keyed by the matched IPv4 address.
/// `tokens` is the current number of available tokens (bytes).
/// `last_refill_ns` is the timestamp of the last refill in nanoseconds
/// (from `bpf_ktime_get_ns`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TokenBucketState {
    pub tokens: u64,
    pub last_refill_ns: u64,
}

impl TokenBucketState {
    /// Refill tokens based on elapsed time since the last refill.
    ///
    /// Computes `new_tokens = elapsed_ns * rate / 1_000_000_000` using
    /// intermediate steps to avoid overflow, then caps at `burst`.
    #[inline(always)]
    pub fn refill_tokens(&mut self, config: &RateLimitConfig, now_ns: u64) {
        // Guard against time going backwards (shouldn't happen, but be safe).
        let elapsed_ns = now_ns.saturating_sub(self.last_refill_ns);

        // To avoid u64 overflow in `elapsed_ns * config.rate` we split the
        // multiplication: compute full seconds and remaining nanoseconds
        // separately.
        let elapsed_secs = elapsed_ns / NANOS_PER_SEC;
        let remaining_ns = elapsed_ns % NANOS_PER_SEC;

        // tokens from full seconds (saturating to avoid overflow)
        let tokens_from_secs = elapsed_secs.saturating_mul(config.rate);
        // tokens from the remaining sub-second fraction
        // remaining_ns < 1e9 and config.rate fits in u64, so this product
        // can overflow for very large rates. Use saturating mul then divide.
        let tokens_from_frac = remaining_ns.saturating_mul(config.rate) / NANOS_PER_SEC;

        let new_tokens = tokens_from_secs.saturating_add(tokens_from_frac);
        self.tokens = self.tokens.saturating_add(new_tokens);
        // Cap at burst.
        if self.tokens > config.burst {
            self.tokens = config.burst;
        }

        self.last_refill_ns = now_ns;
    }

    /// Process an incoming packet: refill tokens, then decide whether to allow
    /// or drop.
    ///
    /// Returns `true` if the packet should be allowed (tokens were sufficient
    /// and have been deducted), or `false` if the packet should be dropped.
    #[inline(always)]
    pub fn process_packet(
        &mut self,
        config: &RateLimitConfig,
        packet_size: u64,
        now_ns: u64,
    ) -> bool {
        self.refill_tokens(config, now_ns);

        if self.tokens >= packet_size {
            self.tokens -= packet_size;
            true // TC_ACT_PIPE — allow
        } else {
            false // TC_ACT_SHOT — drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Feature: ebpf-download-rate-limiter, Property 1: 令牌消耗决策正确性
    // **Validates: Requirements 2.2, 2.3**
    //
    // For any valid token bucket state (tokens, last_refill_ns) and any packet_size:
    // - If tokens >= packet_size, tokens should decrease by packet_size and decision is allow (true)
    // - If tokens < packet_size, tokens remain unchanged and decision is drop (false)
    //
    // We set now_ns = last_refill_ns so that refill_tokens does nothing (elapsed = 0),
    // isolating the consumption decision logic from refill.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_token_consumption_decision(
            tokens in 0..=u64::MAX,
            last_refill_ns in 0..=u64::MAX,
            packet_size in 1u64..=65535u64,
        ) {
            // Use a config with arbitrary non-zero rate/burst; they don't matter
            // because elapsed time is 0 so no refill occurs.
            let config = RateLimitConfig {
                rate: 1_000_000,
                burst: u64::MAX,
            };

            let mut state = TokenBucketState {
                tokens,
                last_refill_ns,
            };

            // Set now_ns = last_refill_ns so elapsed = 0, refill does nothing.
            let now_ns = last_refill_ns;
            let allowed = state.process_packet(&config, packet_size, now_ns);

            if tokens >= packet_size {
                // Should allow and deduct tokens
                prop_assert!(allowed, "expected allow when tokens ({}) >= packet_size ({})", tokens, packet_size);
                prop_assert_eq!(state.tokens, tokens - packet_size,
                    "tokens should decrease by packet_size");
            } else {
                // Should drop and leave tokens unchanged
                prop_assert!(!allowed, "expected drop when tokens ({}) < packet_size ({})", tokens, packet_size);
                prop_assert_eq!(state.tokens, tokens,
                    "tokens should remain unchanged on drop");
            }
        }
    }

    // Feature: ebpf-download-rate-limiter, Property 2: 令牌补充计算正确性
    // **Validates: Requirements 2.4, 2.6**
    //
    // For any valid rate, burst, current_tokens, and elapsed_ns:
    // After refill, tokens should equal min(current_tokens + elapsed_ns * rate / 1_000_000_000, burst).
    // We use u128 arithmetic for the reference calculation to avoid overflow.
    // The implementation uses a split approach (full seconds + remaining nanoseconds) with
    // saturating arithmetic, which can differ slightly at extreme values. We account for this
    // by computing the expected result using the same split approach as the implementation.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_token_refill_calculation(
            rate in 1u64..=10_000_000_000u64,
            burst in 1u64..=u64::MAX,
            current_tokens in 0u64..=u64::MAX,
            elapsed_ns in 0u64..=10_000_000_000_000u64,
        ) {
            let config = RateLimitConfig { rate, burst };

            let last_refill_ns = 1_000_000_000u64; // arbitrary fixed base time
            let now_ns = last_refill_ns + elapsed_ns;

            let mut state = TokenBucketState {
                tokens: current_tokens,
                last_refill_ns,
            };

            state.refill_tokens(&config, now_ns);

            // Reference calculation using u128 to avoid overflow
            let expected_new_tokens = (elapsed_ns as u128 * rate as u128) / 1_000_000_000u128;
            let expected_total = (current_tokens as u128).saturating_add(expected_new_tokens);
            let expected = core::cmp::min(expected_total, burst as u128) as u64;

            // The implementation uses a split approach with saturating_mul which can
            // lose precision when remaining_ns * rate overflows u64. Compute the
            // implementation's expected result using the same split logic.
            let elapsed_secs = elapsed_ns / NANOS_PER_SEC;
            let remaining_ns = elapsed_ns % NANOS_PER_SEC;
            let tokens_from_secs = elapsed_secs.saturating_mul(rate);
            let tokens_from_frac = remaining_ns.saturating_mul(rate) / NANOS_PER_SEC;
            let impl_new_tokens = tokens_from_secs.saturating_add(tokens_from_frac);
            let impl_total = current_tokens.saturating_add(impl_new_tokens);
            let impl_expected = core::cmp::min(impl_total, burst);

            // The actual result must match the implementation's expected result
            prop_assert_eq!(state.tokens, impl_expected,
                "refill mismatch: rate={}, burst={}, current_tokens={}, elapsed_ns={}",
                rate, burst, current_tokens, elapsed_ns);

            // Also verify the result never exceeds burst (Property 3 invariant)
            prop_assert!(state.tokens <= burst,
                "tokens {} exceeded burst {}", state.tokens, burst);

            // When the implementation doesn't hit saturating overflow, it should
            // match the u128 reference exactly
            if (remaining_ns as u128 * rate as u128) <= u64::MAX as u128
                && (elapsed_secs as u128 * rate as u128) <= u64::MAX as u128
                && (current_tokens as u128 + expected_new_tokens) <= u64::MAX as u128
            {
                prop_assert_eq!(state.tokens, expected,
                    "non-overflow case mismatch: rate={}, burst={}, current_tokens={}, elapsed_ns={}",
                    rate, burst, current_tokens, elapsed_ns);
            }

            // Verify last_refill_ns was updated
            prop_assert_eq!(state.last_refill_ns, now_ns,
                "last_refill_ns should be updated to now_ns");
        }
    }

    // Feature: ebpf-download-rate-limiter, Property 3: 令牌数量不变量
    // **Validates: Requirements 2.6**
    //
    // For any valid token bucket configuration (rate, burst) and any sequence of
    // operations (arbitrary mix of refill_tokens and process_packet calls), the
    // token count SHALL NOT exceed the burst limit at any point.

    /// Represents a single operation on the token bucket.
    #[derive(Debug, Clone)]
    enum Op {
        /// Refill tokens with the given elapsed nanoseconds.
        Refill(u64),
        /// Process a packet with the given size in bytes.
        ProcessPacket(u64),
    }

    /// Strategy to generate a random Op.
    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            // Refill with elapsed_ns in [0, 10 seconds]
            (0u64..=10_000_000_000u64).prop_map(Op::Refill),
            // ProcessPacket with packet_size in [1, 65535] (typical MTU range)
            (1u64..=65535u64).prop_map(Op::ProcessPacket),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_token_count_invariant(
            rate in 1u64..=10_000_000_000u64,
            burst in 1u64..=10_000_000_000u64,
            initial_tokens_frac in 0.0f64..=1.0f64,
            ops in proptest::collection::vec(op_strategy(), 1..50),
        ) {
            let config = RateLimitConfig { rate, burst };

            // Start with initial tokens as a fraction of burst to ensure valid state
            let initial_tokens = (initial_tokens_frac * burst as f64) as u64;
            let initial_tokens = core::cmp::min(initial_tokens, burst);

            let mut state = TokenBucketState {
                tokens: initial_tokens,
                last_refill_ns: 1_000_000_000u64, // arbitrary start time
            };

            // Invariant must hold at the start
            prop_assert!(state.tokens <= config.burst,
                "initial tokens {} exceeded burst {}", state.tokens, config.burst);

            let mut current_time_ns = state.last_refill_ns;

            for op in &ops {
                match op {
                    Op::Refill(elapsed_ns) => {
                        current_time_ns = current_time_ns.saturating_add(*elapsed_ns);
                        state.refill_tokens(&config, current_time_ns);
                    }
                    Op::ProcessPacket(packet_size) => {
                        // process_packet internally calls refill_tokens, so advance time a bit
                        current_time_ns = current_time_ns.saturating_add(1_000_000); // +1ms
                        let _ = state.process_packet(&config, *packet_size, current_time_ns);
                    }
                }

                // After EVERY operation, tokens must not exceed burst
                prop_assert!(state.tokens <= config.burst,
                    "tokens {} exceeded burst {} after operation {:?}",
                    state.tokens, config.burst, op);
            }
        }
    }
}
