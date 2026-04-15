// Feature: ebpf-download-rate-limiter, Property 5: 规则管理一致性
// **Validates: Requirements 4.5, 4.6**
//
// For any set of valid rate-limit rules, after adding all rules the list
// operation should return exactly that set. After deleting one rule, the
// list should return the original set minus the deleted rule.
//
// Tested against an InMemoryRuleStore that mirrors MapManager's add/delete/list
// logic, since the real MapManager requires Linux BPF maps (aya LpmTrie).

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use proptest::prelude::*;
use qos_common::LpmKeyV4;

/// Minimal rule info matching the protocol's RuleInfo.
#[derive(Debug, Clone, PartialEq)]
struct RuleInfo {
    ip: String,
    rate: u64,
    burst: u64,
}

// --- CIDR helpers (same logic as qos/src/protocol.rs) ---

fn parse_cidr(s: &str) -> Result<LpmKeyV4> {
    let (addr_str, prefix_len) = if let Some((a, p)) = s.split_once('/') {
        let prefix_len: u32 = p
            .parse()
            .map_err(|_| anyhow!("invalid prefix length: {}", p))?;
        if prefix_len > 32 {
            return Err(anyhow!("prefix length {} out of range (0-32)", prefix_len));
        }
        (a, prefix_len)
    } else {
        (s, 32)
    };

    let addr: std::net::Ipv4Addr = addr_str
        .parse()
        .map_err(|_| anyhow!("invalid IPv4 address: {}", addr_str))?;

    let addr_bits = u32::from(addr);
    let addr_be = addr_bits.to_be();

    Ok(LpmKeyV4 {
        prefix_len,
        addr: addr_be,
    })
}

fn format_cidr(key: &LpmKeyV4) -> String {
    let addr = std::net::Ipv4Addr::from(u32::from_be(key.addr));
    format!("{}/{}", addr, key.prefix_len)
}

// --- InMemoryRuleStore ---

/// In-memory rule store that mirrors MapManager's add/delete/list logic.
///
/// Uses a HashMap keyed by the canonical CIDR string (after parse+format
/// roundtrip) so that equivalent CIDR inputs map to the same entry, just
/// like the real LPM Trie keyed by (prefix_len, addr).
struct InMemoryRuleStore {
    rules: HashMap<String, (u64, u64)>,
}

impl InMemoryRuleStore {
    fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    fn add_rule(&mut self, cidr: &str, rate: u64, burst: u64) -> Result<()> {
        let key = parse_cidr(cidr)?;
        let canonical = format_cidr(&key);
        self.rules.insert(canonical, (rate, burst));
        Ok(())
    }

    fn delete_rule(&mut self, cidr: &str) -> Result<()> {
        let key = parse_cidr(cidr)?;
        let canonical = format_cidr(&key);
        self.rules
            .remove(&canonical)
            .ok_or_else(|| anyhow!("rule not found: {}", cidr))?;
        Ok(())
    }

    fn list_rules(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|(ip, (rate, burst))| RuleInfo {
                ip: ip.clone(),
                rate: *rate,
                burst: *burst,
            })
            .collect()
    }
}

// --- Property test ---

/// Generate a valid CIDR string with associated rate and burst values.
fn cidr_rule_strategy() -> impl Strategy<Value = (String, u64, u64)> {
    (
        0u8..=255u8,
        0u8..=255u8,
        0u8..=255u8,
        0u8..=255u8,
        0u32..=32u32,
        1u64..=10_000_000_000u64,
        1u64..=10_000_000_000u64,
    )
        .prop_map(|(a, b, c, d, prefix, rate, burst)| {
            let cidr = format!("{}.{}.{}.{}/{}", a, b, c, d, prefix);
            (cidr, rate, burst)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_rule_management_consistency(
        raw_rules in proptest::collection::vec(cidr_rule_strategy(), 1..20),
        delete_idx_seed in proptest::num::usize::ANY,
    ) {
        let mut store = InMemoryRuleStore::new();

        // Deduplicate by canonical CIDR so we know the expected set.
        // Later adds overwrite earlier ones (same as real map behavior).
        let mut expected: HashMap<String, (u64, u64)> = HashMap::new();
        for (cidr, rate, burst) in &raw_rules {
            store.add_rule(cidr, *rate, *burst).unwrap();
            let key = parse_cidr(cidr).unwrap();
            let canonical = format_cidr(&key);
            expected.insert(canonical, (*rate, *burst));
        }

        // list_rules should return exactly the expected set
        let listed = store.list_rules();
        let listed_map: HashMap<String, (u64, u64)> = listed
            .iter()
            .map(|r| (r.ip.clone(), (r.rate, r.burst)))
            .collect();

        prop_assert_eq!(
            listed_map.len(),
            expected.len(),
            "list length mismatch after adds: got {}, expected {}",
            listed_map.len(),
            expected.len()
        );
        for (ip, (rate, burst)) in &expected {
            let got = listed_map.get(ip);
            prop_assert_eq!(
                got,
                Some(&(*rate, *burst)),
                "missing or mismatched rule for {} after adds",
                ip
            );
        }

        // Now delete one rule
        if !expected.is_empty() {
            let keys: Vec<String> = expected.keys().cloned().collect();
            let delete_idx = delete_idx_seed % keys.len();
            let to_delete = &keys[delete_idx];

            store.delete_rule(to_delete).unwrap();
            expected.remove(to_delete);

            let listed_after = store.list_rules();
            let listed_after_map: HashMap<String, (u64, u64)> = listed_after
                .iter()
                .map(|r| (r.ip.clone(), (r.rate, r.burst)))
                .collect();

            prop_assert_eq!(
                listed_after_map.len(),
                expected.len(),
                "list length mismatch after delete: got {}, expected {}",
                listed_after_map.len(),
                expected.len()
            );
            prop_assert!(
                !listed_after_map.contains_key(to_delete),
                "deleted rule {} still present in list",
                to_delete
            );
            for (ip, (rate, burst)) in &expected {
                let got = listed_after_map.get(ip);
                prop_assert_eq!(
                    got,
                    Some(&(*rate, *burst)),
                    "missing or mismatched rule for {} after delete",
                    ip
                );
            }
        }
    }
}
