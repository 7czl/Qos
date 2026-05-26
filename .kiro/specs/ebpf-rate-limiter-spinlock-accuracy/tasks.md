# Implementation Plan: eBPF 限速器准确性升级（共享条目 + bpf_spin_lock）

## Overview

本升级是对既有 `ebpf-download-rate-limiter` 数据面的**最小侵入式准确性改造**：

- `qos-common`：在 `TokenBucketState` 顶层嵌入 `bpf_spin_lock` 字段，保留既有纯算术 API（`refill_tokens` / `process_packet`）以维护既有属性测试。
- `qos-ebpf`：将 `TOKENS_INGRESS` / `TOKENS_EGRESS` 由 `PerCpuHashMap` 改为 `HashMap`（`BPF_MAP_TYPE_HASH`），重写 `try_ingress` / `try_egress` 为"锁外采样时间 → 乐观插入首包 → 锁内 RMW"流程，refill 与扣减逻辑展开为锁内内联代码。
- `qos`：补强 `tc_ingress` / `tc_egress` 加载错误路径，把 verifier 文本与程序名透传出去并以非零退出码失败（Requirement 2.5）。
- 新增两条用户态属性测试（Property A / B）覆盖 Requirement 3.1 / 3.2 / 3.3 / 3.4，并补充 Linux + root 环境下的集成测试覆盖端到端 ±2% 验收。
- `MapManager`、UDS 协议、CLI 参数与既有客户端**完全不变**（Requirement 4）。

任务推进顺序为：先升级共享数据结构（qos-common），再切换数据面（qos-ebpf），同时独立增强 Loader 错误处理（qos），随后补全属性测试与端到端集成测试，最后回归。

## Tasks

- [x] 1. 升级 qos-common 数据模型
  - [x] 1.1 在 `TokenBucketState` 顶层嵌入 `bpf_spin_lock` 字段
    - 在 `qos-common/Cargo.toml` 中新增对 `aya-ebpf-bindings` 的 `no_std` 依赖（用于复用 `bpf_spin_lock` 结构体），并在 `feature = "user"` 下启用与 userspace 相同布局的 POD 暴露。
    - 修改 `qos-common/src/lib.rs` 中的 `TokenBucketState`，按 `#[repr(C)]` 顺序声明字段为 `lock: bpf_spin_lock`、`tokens: u64`、`last_refill_ns: u64`，并保持 `#[derive(Clone, Copy, Debug)]`。
    - 在 `feature = "user"` 下为新版 `TokenBucketState` 实现 `unsafe impl aya::Pod`。
    - 保留既有 `refill_tokens` / `process_packet` 纯算术方法不变，确保既有属性测试 Property 1/2/3 继续编译通过且不依赖 `lock` 字段。
    - 更新 `TokenBucketState` 的 doc comment，说明新增 `lock` 字段及其 `bpf_spin_lock` 使用约束。
    - _需求：1.4, 2.1_

  - [x] 1.2 编写 `TokenBucketState` 内存布局单元测试
    - 在 `qos-common/src/lib.rs` 的 `tests` 模块中新增 `#[test] fn token_bucket_state_layout()`。
    - 断言 `core::mem::offset_of!(TokenBucketState, lock) == 0`。
    - 断言 `core::mem::align_of::<TokenBucketState>() >= 4` 且 `core::mem::align_of::<TokenBucketState>() % 4 == 0`。
    - 断言 `core::mem::size_of::<TokenBucketState>() == 24`。
    - _需求：2.1_

- [x] 2. 改造 qos-ebpf 数据面（共享条目 + bpf_spin_lock）
  - [x] 2.1 切换 `TOKENS_*` map 类型并提取共享 RMW 辅助函数
    - 在 `qos-ebpf/src/main.rs` 中将 `TOKENS_INGRESS` 与 `TOKENS_EGRESS` 的类型由 `PerCpuHashMap<u32, TokenBucketState>` 改为 `HashMap<u32, TokenBucketState>`，保持 `max_entries = 1024` 与 flag 不变。
    - 引入对 `aya_ebpf::maps::HashMap` 与 `aya_ebpf::helpers::{bpf_spin_lock, bpf_spin_unlock}` 的 use 声明。
    - 抽出辅助函数 `try_one(map: &HashMap<u32, TokenBucketState>, ip: u32, config: &RateLimitConfig, packet_len: u64) -> Result<i32, ()>`，实现"锁外 `bpf_ktime_get_ns` 采样 → 锁外 `get_ptr` 探测 → 锁外乐观 `insert` 初值 `{lock: 0, tokens: burst, last_refill_ns: now}` → 锁外二次 `get_ptr_mut`（拿不到则返回 `TC_ACT_PIPE` fail-open）→ 锁内将 refill 算术与扣减逻辑展开为内联表达式 → 写回 `tokens` 与 `last_refill_ns` → `bpf_spin_unlock` → 锁外根据 `allowed` 布尔返回 `TC_ACT_PIPE` / `TC_ACT_SHOT`"。
    - 在 `try_one` 锁内严禁任何 helper 调用与 BPF-to-BPF 调用；refill 算术须使用与 `qos-common::TokenBucketState::refill_tokens` 等价的 split-multiplication 实现（`elapsed_secs * rate + remaining_ns * rate / NANOS_PER_SEC`，含同样的溢出保护），并在所有分支汇合到唯一的 unlock 站点。
    - _需求：1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4_

  - [x] 2.2 重写 `try_ingress` / `try_egress` 主循环以共享 entry 与 `try_one` 串行化
    - 重写 `try_ingress`：解析 IPv4 头取 `src_addr` 与 `packet_len`，命中 `RULES_INGRESS` 后调用 `try_one(&TOKENS_INGRESS, src_addr, config, packet_len)`；未命中 LPM 时直接返回 `TC_ACT_PIPE` 且**不**触发 `TOKENS_INGRESS` 的任何读写。
    - 重写 `try_egress`：解析 IPv4 头取 `dst_addr` 与 `packet_len`，命中 `RULES_EGRESS` 后调用 `try_one(&TOKENS_EGRESS, dst_addr, config, packet_len)`；未命中时同样不触碰 `TOKENS_EGRESS`。
    - 删除既有 per-CPU 路径的 fallback 写法；保留解析失败 / 错误路径仍返回 `TC_ACT_PIPE` 的既有 fail-open 语义。
    - 通过 `cargo build -p qos`（触发 aya-build 编译 `qos-ebpf`）确认 verifier 接受两个程序。
    - _需求：1.1, 1.2, 1.5, 2.2, 2.3, 2.4, 3.3, 3.4_

- [~] 3. 检查点 - 确保 eBPF 编译并被 verifier 接受 (跳过 — 需要 Linux + bpf-linker + 内核 verifier，本机为 macOS)
  - 运行 `cargo build` 触发 `qos-ebpf` 通过 aya-build 编译，确保 verifier 不拒绝 `tc_ingress` / `tc_egress`。如有问题请询问用户。

- [x] 4. 增强 Loader 错误透传（Requirement 2.5）
  - [x] 4.1 改进 `qos/src/main.rs` 中 `tc_ingress` / `tc_egress` 的加载与挂载错误路径
    - 在 `program_mut("tc_ingress")` / `program_mut("tc_egress")` 后的 `load()` / `attach()` 调用上分别包一层显式 `match`，失败时使用 `log::error!("failed to load {prog_name}: {err:#}")`（其中 `prog_name` 为 `"tc_ingress"` 或 `"tc_egress"`，`{err:#}` 启用 alternate Debug 以输出完整 anyhow cause chain，从而把 verifier 文本透传到 stderr）。
    - 失败时使用 `anyhow::Error::context` 附加 `"eBPF verifier rejected {prog_name}"` 信息后向上 `?` 传播，使 `main` 以非零退出码退出。
    - 不修改 `--iface` / `--socket-path` 的参数定义、默认值或 `/var/run/qos.sock` 路径，避免回归 Requirement 4.6。
    - _需求：2.5, 4.6_

- [~] 5. 准确性属性测试（PBT）
  - [~] 5.1 编写 Property A 长程速率收敛属性测试 (跳过 — 可选)
    - 在 `qos-common/tests/property_rate_accuracy.rs` 中新建 `proptest!` 测试 `property_rate_accuracy_within_2pct`。
    - **属性 A：令牌桶长程平均速率收敛于 Configured_Rate**
    - **验证需求：3.1, 3.2, 3.4**
    - 用 `std::sync::Mutex<TokenBucketState>` 作为 `bpf_spin_lock` 的用户态等价物；以单调推进的"模拟时钟"`now_ns` 替代 `bpf_ktime_get_ns()`。
    - 生成器：`R ∈ [1KB/s, 100MB/s]`、`B ∈ [R, 10R]`、`C ∈ {1, 2, 4, 8}`、模拟时长 `T ∈ [10s, 30s]`、包尺寸均匀 `[64, 1500]`。
    - 启动 `C` 个 worker（线程或顺序模拟），每个独立采样时钟、生成 >R 的负载，以等价于 spinlock 的互斥语义对共享状态执行 refill + spend + writeback。
    - 在尾部 10 秒窗口断言 `R * 0.98 ≤ B_passed / T ≤ R * 1.02`。
    - `ProptestConfig::with_cases(100)`。

  - [x] 5.2 编写 Property B 无匹配规则不副作用属性测试
    - 在 `qos-common/tests/property_no_match_no_op.rs` 中新建 `proptest!` 测试 `property_no_match_leaves_token_map_unchanged`。
    - **属性 B：无匹配规则的包不修改 Shared_Token_Map**
    - **验证需求：3.3**
    - 实现一个用户态 `try_decision_model(direction, rules: &LpmTrieModel, tokens: &mut HashMap<u32, TokenBucketState>, ip, packet_len) -> i32`，与 `try_one` 行为同构（命中前不触碰 `tokens`；未命中直接返回 `TC_ACT_PIPE`）。
    - 生成器：随机 1..16 条 LPM 规则、随机包尺寸、随机 IPv4 地址；用 `prop_filter` 排除任何被规则集合覆盖的地址。
    - 调用 model 一次后断言：返回值等于 `TC_ACT_PIPE`，且 `tokens` 的 key 集合与每个 entry 的 `tokens` / `last_refill_ns` 与调用前**字节相等**。
    - `ProptestConfig::with_cases(100)`。

- [-] 6. 检查点 - 确保 qos-common 与用户态测试通过
  - 运行 `cargo test -p qos-common`（含既有 Property 1/2/3 与新增 A/B 的回归）以及 `cargo test -p qos`，确保所有测试通过。如有问题请询问用户。

- [~] 7. 集成 / 端到端测试（需要 Linux + root + netns） (跳过 — 可选，需要 Linux+root)
  - [~] 7.1 编写 BPF 加载与 map 元数据 SMOKE 测试 (跳过)
    - 在 `qos/tests/load_smoke.rs` 中新增 `#[ignore]` 测试 `tc_programs_pass_verifier`。
    - 用 `aya::Ebpf::load(...)` 加载（不挂载）由 `qos-ebpf` 构建出的字节码，分别 `program_mut("tc_ingress")` / `program_mut("tc_egress")`，断言两次 `try_into::<SchedClassifier>()?.load()` 均 `Ok` —— 等价于 verifier 接受了带锁逻辑（覆盖 Requirement 2.1, 2.2, 2.3, 2.4 的静态保证）。
    - 通过 `bpf.map("TOKENS_INGRESS")` / `bpf.map("TOKENS_EGRESS")` 读取 `MapInfo`，断言 `map_type == BPF_MAP_TYPE_HASH`、`max_entries == 1024`。
    - _验证需求：1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 2.4_

  - [~] 7.2 实现 netns / veth 集成测试 harness (跳过)
    - 在 `qos/tests/common/mod.rs` 新增辅助模块，实现：创建 `qos-tx` / `qos-rx` 命名空间与 `veth_tx` / `veth_rx` 配对、在 `qos-tx` 内启动 `qos --iface veth_tx --socket-path <tmp>`、通过 UDS 客户端发送 `add` / `delete` / `list`、用 `taskset` 绑核启动 sender、在 `qos-rx` 启动 `recv.py` 并解析其 stderr 末次 `received / elapsed` 输出、提供 `assert_within_tolerance(measured, configured, 0.02)`。
    - 在 setup / teardown 中负责删除 socket 文件、销毁 namespace、清理 veth 与残留 qos 进程。
    - 所有暴露的测试入口标注 `#[ignore]`，以便普通 `cargo test` 不执行；CI 上由专用 job 用 `cargo test -- --ignored` 触发。

  - [~] 7.3 单核 ±2% 准确性集成测试（ingress + egress）(跳过)
    - 在 `qos/tests/integration_accuracy_single.rs` 中新增两个 `#[ignore]` 测试 `it_ingress_single_core_1mbs` 与 `it_egress_single_core_10mbs`。
    - 使用 7.2 提供的 harness 关闭 RPS / XPS（`echo 1 > /sys/class/net/veth_tx/queues/rx-0/rps_cpus`、`echo 0 > /sys/class/net/veth_tx/queues/tx-0/xps_cpus`），用 `taskset -c 0` 绑定 sender 到 CPU 0。
    - 持续提供 >R 的负载至少 10 秒，断言 `recv.py` 测得的尾部 10 秒窗口均值落入 `[R * 0.98, R * 1.02]`。
    - _验证需求：3.1, 3.4_

  - [~] 7.4 多核 ±2% 准确性集成测试（ingress + egress）(跳过)
    - 在 `qos/tests/integration_accuracy_multi.rs` 中新增两个 `#[ignore]` 测试 `it_ingress_multi_core_1mbs` 与 `it_egress_multi_core_10mbs`。
    - 使用 7.2 提供的 harness 启用 4 核 RPS（`echo f > /sys/class/net/veth_tx/queues/rx-0/rps_cpus`），并以 `taskset -c 0..3` 启动 4 个并发 sender 进程同时打满同一条规则。
    - 断言 `recv.py` 尾部 10 秒窗口均值落入 `[R * 0.98, R * 1.02]`，验证锁串行化在多核竞争下消除了 N 倍放大。
    - _验证需求：3.2, 3.4_

  - [~] 7.5 边界场景集成测试（无匹配 / 首包初始化 / Verifier 拒绝）(跳过)
    - 在 `qos/tests/integration_edge_cases.rs` 中新增三个 `#[ignore]` 测试：
      - `it_no_rule_no_throttle`：未通过 UDS 安装任何规则时，单核单流量测得 `recv.py` 吞吐 ≥ 接口理论上限的 90%（验证 Requirement 3.3 端到端）。
      - `it_first_packet_init`：安装规则后只发送 1 个匹配包，通过 `bpftool map dump name TOKENS_INGRESS`（或 aya `MapData::iter`）读取唯一 entry，断言 `tokens == burst` 且 `last_refill_ns ∈ [t_before, t_after]`（覆盖 Requirement 1.4）。
      - `it_verifier_reject_dummy`：构造一个故意持锁未释放的 dummy ELF（例如在 `qos/tests/fixtures/` 下提供预先编译的损坏字节码）调用 `aya::Ebpf::load_file`，把 dummy 程序名替换为 `tc_ingress` 后调用 7.2 的 harness 启动 `qos`；断言进程退出码 ≠ 0 且 stderr 含字符串 `tc_ingress` 与 verifier 文本片段（覆盖 Requirement 2.5）。
    - _验证需求：1.4, 2.5, 3.3_

- [-] 8. 最终检查点 - 全量回归
  - 运行 `cargo build`、`cargo test -p qos-common`、`cargo test -p qos`、（可选）`cargo test -- --ignored`（要求 Linux + root 自托管 runner），确保既有属性测试 1-7 与本升级新增的属性测试 A、B 全部通过，并且端到端 ±2% 验收成立。如有问题请询问用户。

## Notes

- 标记 `*` 的子任务为可选项（含全部测试任务），可在 MVP 阶段跳过；核心实现任务（1.1, 2.1, 2.2, 4.1）不可跳过。
- 每个任务标注了它所验证或满足的需求条款，确保可追溯性。
- 7.x 集成测试需要 Linux 内核 ≥ 5.4、root 权限与 `iproute2` / `taskset` / `python3` / `bpf-linker`，建议在自托管 CI runner 上执行。
- 既有的 `MapManager`、UDS 协议、CLI 参数与客户端脚本不在本任务列表内做任何修改，由 Requirement 4 的兼容性约束保护。
- 锁内禁止任何 helper 与 BPF-to-BPF 调用：`bpf_ktime_get_ns()` 必须在 `bpf_spin_lock` 之前采样、refill 算术必须展开为内联表达式（不依赖 `#[inline(always)]` 提示）。

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "4.1"] },
    { "id": 1, "tasks": ["1.2", "2.1", "5.1", "5.2"] },
    { "id": 2, "tasks": ["2.2"] },
    { "id": 3, "tasks": ["7.1", "7.2"] },
    { "id": 4, "tasks": ["7.3", "7.4", "7.5"] }
  ]
}
```
