# Requirements Document

## Introduction

既有 ebpf-download-rate-limiter 之数据面将令牌桶状态储于 `PerCpuHashMap<u32, TokenBucketState>`，每核各持其副本独立计数。同一 IP 之流量若被分派至 N 核（RPS/RSS 多队列、softirq 跨核唤醒等情形），则 N 个独立令牌桶各自补充与消耗，致实测放行速率约为配置值之 N 倍——实测 1MB/s 配置出现 ~4MB/s 之放行（4x 误差）。

本 spec 为既有限速器之**准确性升级**，将 ingress 与 egress 两条数据路径之令牌桶状态由 per-CPU 改为单一共享条目，并以 eBPF `bpf_spin_lock` 序列化"读—补—消—写"四步，使配置速率与实测放行速率之偏差控制在 ±2% 以内。本升级**不变更** UDS 控制协议、`MapManager` 规则管理 API 与 LPM Trie 规则结构；既有客户端（含 `recv.py`、运维脚本）无需任何修改。

## Glossary

- **Rate_Limiter**: the eBPF TC classifier programs `tc_ingress` and `tc_egress` defined in `qos-ebpf/src/main.rs` that enforce per-rule token bucket limits in the kernel data path.
- **Shared_Token_Map**: a non-per-CPU BPF map of type `BPF_MAP_TYPE_HASH` keyed by IPv4 address (`u32`), holding a single `TokenBucketState` value per matched IP that is shared across all CPUs.
- **Token_Bucket_State**: the kernel struct holding `tokens: u64`, `last_refill_ns: u64`, and a `bpf_spin_lock` field used to serialize updates to that entry.
- **Configured_Rate**: the `rate` field (bytes per second) supplied via the UDS `add` command.
- **Configured_Burst**: the `burst` field (bytes) supplied via the UDS `add` command.
- **Effective_Rate**: the user-space-measured byte-per-second throughput of packets returned with `TC_ACT_PIPE` for a single rule, averaged over the trailing 10-second window.
- **Accuracy_Tolerance**: the maximum allowed absolute deviation of Effective_Rate from Configured_Rate, expressed as a percentage of Configured_Rate.
- **UDS_Protocol**: the JSON-over-Unix-Domain-Socket request/response protocol defined in the existing `ebpf-download-rate-limiter` spec, including the `add`, `delete`, `list` commands and the `direction` field.
- **Rule_Management_API**: the user-facing `MapManager::add_rule`, `delete_rule`, `list_rules` methods in `qos/src/map_manager.rs`, together with the UDS_Protocol surface they back.
- **Verifier**: the in-kernel BPF verifier that statically validates eBPF programs and their map access patterns at program load time.
- **Loader**: the user-space `qos` binary defined in `qos/src/main.rs` that loads and attaches the Rate_Limiter programs.

## Requirements

### Requirement 1: 共享令牌桶状态映射

**User Story:** As a network operator, I want a single token bucket state per limited IP that is shared across all CPU cores, so that the configured rate is enforced as a global limit instead of being multiplied by the number of cores receiving traffic.

#### Acceptance Criteria

1. THE Rate_Limiter SHALL store Token_Bucket_State entries for the ingress data path in a Shared_Token_Map of BPF map type `BPF_MAP_TYPE_HASH`.
2. THE Rate_Limiter SHALL store Token_Bucket_State entries for the egress data path in a Shared_Token_Map of BPF map type `BPF_MAP_TYPE_HASH`.
3. THE Shared_Token_Map SHALL support a maximum of 1024 entries per direction.
4. WHEN the Rate_Limiter processes a packet whose matched IPv4 address has no existing entry in the Shared_Token_Map, THE Rate_Limiter SHALL initialize a new entry with `tokens` set to Configured_Burst and `last_refill_ns` set to the value returned by `bpf_ktime_get_ns()` at the time of insertion.
5. THE Rate_Limiter SHALL key the Shared_Token_Map by the source IPv4 address for the ingress data path and by the destination IPv4 address for the egress data path.

### Requirement 2: 自旋锁保护令牌桶读—改—写

**User Story:** As a network operator, I want concurrent token bucket updates from packets handled on different CPUs to be serialized within the kernel, so that no tokens are double-spent or double-credited under parallel traffic.

#### Acceptance Criteria

1. THE Token_Bucket_State SHALL contain a `bpf_spin_lock` field placed in a layout accepted by the Verifier for use with `BPF_MAP_TYPE_HASH` values.
2. WHEN the Rate_Limiter looks up a Token_Bucket_State entry to refill and consume tokens, THE Rate_Limiter SHALL acquire the entry's `bpf_spin_lock` before reading or writing `tokens` or `last_refill_ns`.
3. WHILE the `bpf_spin_lock` of a Token_Bucket_State entry is held, THE Rate_Limiter SHALL complete the refill computation, the allow-or-drop decision, and the write-back of `tokens` and `last_refill_ns` before releasing the lock.
4. THE Rate_Limiter SHALL release the `bpf_spin_lock` of a Token_Bucket_State entry on every code path that successfully acquired the lock — including the allow path, the drop path, and any early-return path inserted for verifier or robustness reasons — and SHALL NOT issue a release on any code path where acquisition did not succeed.
5. IF the Verifier rejects the locked Rate_Limiter program at load time, THEN THE Loader SHALL exit with a non-zero status code and SHALL emit a log message at `error` level containing the affected program name (`tc_ingress` or `tc_egress`) and the verifier message text.

### Requirement 3: 限速准确性目标

**User Story:** As a network operator, I want the measured throughput to track the configured rate, so that the bandwidth budgets I set actually hold under real traffic instead of being silently exceeded by a multiple of the core count.

#### Acceptance Criteria

1. WHEN a single rule with Configured_Rate `R` and Configured_Burst `B` is installed in one direction, an offered load strictly greater than `R` is sustained for at least 10 seconds, and the matched flow is processed on a single CPU, THE Rate_Limiter SHALL produce an Effective_Rate within ±2% of `R` measured over the trailing 10-second window.
2. WHEN a single rule with Configured_Rate `R` and Configured_Burst `B` is installed in one direction, an offered load strictly greater than `R` is sustained for at least 10 seconds, and the matched flow is processed across multiple CPUs concurrently, THE Rate_Limiter SHALL produce an Effective_Rate within ±2% of `R` measured over the trailing 10-second window.
3. WHILE no rule in the corresponding LPM Trie matches a packet's source IP (ingress) or destination IP (egress), THE Rate_Limiter SHALL return `TC_ACT_PIPE` and SHALL leave the Shared_Token_Map for that direction unchanged.
4. THE Rate_Limiter SHALL satisfy acceptance criteria 3.1 and 3.2 independently for the ingress data path and for the egress data path.

### Requirement 4: 控制面与协议向后兼容

**User Story:** As an operator with existing tooling and rule files, I want the UDS protocol and rule management commands to remain byte-equivalent across this upgrade, so that I do not need to update clients, scripts, or persisted rules.

#### Acceptance Criteria

1. THE Rule_Management_API SHALL accept the same JSON request shapes for the `add`, `delete`, and `list` commands as defined in the existing `ebpf-download-rate-limiter` spec, including the optional `direction` field with values `download`, `upload`, and `both`.
2. WHEN the Rule_Management_API receives an `add`, `delete`, or `list` request that was successfully handled by the version preceding this upgrade with a given response, THE Rule_Management_API SHALL return a response with the same `status`, `data`, and `message` field shapes for the same input.
3. WHEN an `add` request is received with a given `ip`, `rate`, `burst`, and `direction`, THE Rule_Management_API SHALL install a rule with identical LPM Trie matching semantics on `RULES_INGRESS`, `RULES_EGRESS`, or both, as determined by `direction`, and `delete` and `list` requests SHALL NOT install rules.
4. IF an `add` request would, per its `direction`, target two LPM Trie maps and installation succeeds on one map but fails on the other, THEN THE Rule_Management_API SHALL roll back the successful insertion and SHALL return a response with `status` set to `"error"` and a non-empty `message` field describing the failure.
5. THE Rule_Management_API SHALL preserve the maximum capacity of 1024 entries per LPM Trie map.
6. THE Loader SHALL accept the same `--iface` and `--socket-path` command-line arguments with the same semantics and the same `/var/run/qos.sock` default as before this upgrade.
