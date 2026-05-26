use anyhow::{anyhow, Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::MapData;
use qos_common::RateLimitConfig;

use crate::protocol::{format_cidr, parse_cidr, Direction, RuleInfo};
use qos_common::LpmKeyV4;

/// Manages BPF Map operations for rate-limit rules.
///
/// Holds two independent LPM Trie maps: one for ingress (download) and one for
/// egress (upload). Each direction is managed independently, with optional
/// `Direction::Both` writing to or deleting from both at once.
pub struct MapManager {
    ingress: LpmTrie<MapData, u32, RateLimitConfig>,
    egress: LpmTrie<MapData, u32, RateLimitConfig>,
}

/// Maximum number of entries each LPM Trie map supports.
const MAX_RULES: usize = 1024;

impl MapManager {
    pub fn new(
        ingress: LpmTrie<MapData, u32, RateLimitConfig>,
        egress: LpmTrie<MapData, u32, RateLimitConfig>,
    ) -> Self {
        Self { ingress, egress }
    }

    /// Add a rate-limit rule for the given CIDR in the requested direction(s).
    pub fn add_rule(
        &mut self,
        cidr: &str,
        rate: u64,
        burst: u64,
        direction: Direction,
    ) -> Result<()> {
        let lpm_key = parse_cidr(cidr)?;
        let key = Key::new(lpm_key.prefix_len, lpm_key.addr);
        let config = RateLimitConfig { rate, burst };

        match direction {
            Direction::Download => Self::insert_into(&mut self.ingress, &key, config),
            Direction::Upload => Self::insert_into(&mut self.egress, &key, config),
            Direction::Both => {
                Self::insert_into(&mut self.ingress, &key, config)?;
                Self::insert_into(&mut self.egress, &key, config)
            }
        }
    }

    /// Delete a rate-limit rule for the given CIDR from the requested direction(s).
    ///
    /// For `Direction::Both`, attempts to delete from both maps and ignores
    /// "not found" errors so that a partial state can still be cleaned up.
    pub fn delete_rule(&mut self, cidr: &str, direction: Direction) -> Result<()> {
        let lpm_key = parse_cidr(cidr)?;
        let key = Key::new(lpm_key.prefix_len, lpm_key.addr);

        match direction {
            Direction::Download => Self::remove_from(&mut self.ingress, &key, cidr),
            Direction::Upload => Self::remove_from(&mut self.egress, &key, cidr),
            Direction::Both => {
                let r1 = Self::remove_from(&mut self.ingress, &key, cidr);
                let r2 = Self::remove_from(&mut self.egress, &key, cidr);
                // Succeed if at least one direction had the rule.
                match (r1, r2) {
                    (Ok(()), _) | (_, Ok(())) => Ok(()),
                    (Err(e), _) => Err(e),
                }
            }
        }
    }

    /// List all rate-limit rules.
    ///
    /// If `filter` is `None`, returns rules from both directions.
    /// If `filter` is `Some(direction)`, returns only rules in that direction.
    pub fn list_rules(&self, filter: Option<Direction>) -> Result<Vec<RuleInfo>> {
        let mut rules = Vec::new();

        let want_ingress = matches!(
            filter,
            None | Some(Direction::Download) | Some(Direction::Both)
        );
        let want_egress = matches!(
            filter,
            None | Some(Direction::Upload) | Some(Direction::Both)
        );

        if want_ingress {
            Self::collect_into(&self.ingress, Direction::Download, &mut rules)?;
        }
        if want_egress {
            Self::collect_into(&self.egress, Direction::Upload, &mut rules)?;
        }

        Ok(rules)
    }

    // --- helpers ---

    fn insert_into(
        map: &mut LpmTrie<MapData, u32, RateLimitConfig>,
        key: &Key<u32>,
        config: RateLimitConfig,
    ) -> Result<()> {
        map.insert(key, config, 0).map_err(|e| {
            let s = format!("{}", e);
            if s.contains("ENOSPC") || s.contains("No space") {
                anyhow!("rule limit reached (max {})", MAX_RULES)
            } else {
                anyhow!("failed to insert rule: {}", e)
            }
        })?;
        Ok(())
    }

    fn remove_from(
        map: &mut LpmTrie<MapData, u32, RateLimitConfig>,
        key: &Key<u32>,
        cidr: &str,
    ) -> Result<()> {
        map.remove(key).map_err(|e| {
            let s = format!("{}", e);
            if s.contains("ENOENT") || s.contains("not found") {
                anyhow!("rule not found: {}", cidr)
            } else {
                anyhow!("failed to delete rule: {}", e)
            }
        })?;
        Ok(())
    }

    fn collect_into(
        map: &LpmTrie<MapData, u32, RateLimitConfig>,
        direction: Direction,
        out: &mut Vec<RuleInfo>,
    ) -> Result<()> {
        for result in map.iter() {
            let (key, config) = result.context("failed to read rule from map")?;
            let lpm_key = LpmKeyV4 {
                prefix_len: key.prefix_len(),
                addr: key.data(),
            };
            out.push(RuleInfo {
                ip: format_cidr(&lpm_key),
                rate: config.rate,
                burst: config.burst,
                direction,
            });
        }
        Ok(())
    }
}
