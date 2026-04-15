use anyhow::{anyhow, Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::MapData;
use qos_common::RateLimitConfig;

use crate::protocol::{format_cidr, parse_cidr, RuleInfo};
use qos_common::LpmKeyV4;

/// Manages BPF Map operations for rate-limit rules.
pub struct MapManager {
    rules: LpmTrie<MapData, u32, RateLimitConfig>,
}

/// Maximum number of entries the LPM Trie map supports.
const MAX_RULES: usize = 1024;

impl MapManager {
    /// Create a new MapManager wrapping the given LPM Trie map.
    pub fn new(rules: LpmTrie<MapData, u32, RateLimitConfig>) -> Self {
        Self { rules }
    }

    /// Add a rate-limit rule for the given CIDR.
    pub fn add_rule(&mut self, cidr: &str, rate: u64, burst: u64) -> Result<()> {
        let lpm_key = parse_cidr(cidr)?;
        let key = Key::new(lpm_key.prefix_len, lpm_key.addr);
        let config = RateLimitConfig { rate, burst };

        self.rules.insert(&key, config, 0).map_err(|e| {
            let err_str = format!("{}", e);
            if err_str.contains("ENOSPC") || err_str.contains("No space") {
                anyhow!("rule limit reached (max {})", MAX_RULES)
            } else {
                anyhow!("failed to insert rule: {}", e)
            }
        })?;
        Ok(())
    }

    /// Delete a rate-limit rule for the given CIDR.
    pub fn delete_rule(&mut self, cidr: &str) -> Result<()> {
        let lpm_key = parse_cidr(cidr)?;
        let key = Key::new(lpm_key.prefix_len, lpm_key.addr);

        self.rules.remove(&key).map_err(|e| {
            let err_str = format!("{}", e);
            if err_str.contains("ENOENT") || err_str.contains("not found") {
                anyhow!("rule not found: {}", cidr)
            } else {
                anyhow!("failed to delete rule: {}", e)
            }
        })?;
        Ok(())
    }

    /// List all rate-limit rules currently in the LPM Trie.
    pub fn list_rules(&self) -> Result<Vec<RuleInfo>> {
        let mut rules = Vec::new();

        for result in self.rules.iter() {
            let (key, config) = result.context("failed to read rule from map")?;
            let lpm_key = LpmKeyV4 {
                prefix_len: key.prefix_len(),
                addr: key.data(),
            };
            rules.push(RuleInfo {
                ip: format_cidr(&lpm_key),
                rate: config.rate,
                burst: config.burst,
            });
        }

        Ok(rules)
    }
}
