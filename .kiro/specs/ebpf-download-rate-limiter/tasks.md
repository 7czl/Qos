# 实现计划：eBPF 下载限速器

## 概述

基于 aya 框架实现 eBPF 下载限速器，采用 Rust workspace 结构，分为 qos-common（共享数据结构）、qos-ebpf（eBPF TC 程序）和 qos（用户空间控制面）三个 crate。实现按照从底层共享结构到 eBPF 数据面再到用户空间控制面的顺序推进，最后集成联调。

## 任务

- [x] 1. 搭建 Workspace 结构和基础配置
  - [x] 1.1 重构根 Cargo.toml 为 workspace 配置，创建 qos-common、qos-ebpf、qos 三个 crate 的目录结构和 Cargo.toml
    - 根 Cargo.toml 设置 `[workspace]` members 包含 `qos-common`、`qos`，resolver = "2"
    - qos-ebpf 不加入 workspace members（eBPF 目标不同，由 aya-build 在 build.rs 中编译）
    - 删除根目录下的 `src/main.rs`（不再需要）
    - 创建 `qos-common/Cargo.toml`（no_std 兼容，无外部依赖）
    - 创建 `qos-ebpf/Cargo.toml`（依赖 aya-ebpf、aya-log-ebpf、network-types、qos-common）
    - 创建 `qos-ebpf/rust-toolchain.toml`（nightly 工具链 + rust-src component）
    - 创建 `qos/Cargo.toml`（依赖 aya、tokio、clap、serde、serde_json、anyhow、log、env_logger、qos-common，build-dependencies 包含 aya-build）
    - 创建 `qos/build.rs`（使用 aya-build 编译 qos-ebpf crate）
    - _需求：7.1, 7.2, 7.3, 7.4, 7.5_

- [x] 2. 实现 qos-common 共享数据结构
  - [x] 2.1 在 `qos-common/src/lib.rs` 中定义 LpmKeyV4、RateLimitConfig、TokenBucketState 结构体
    - 使用 `#![no_std]` 确保兼容 eBPF 环境
    - 所有结构体使用 `#[repr(C)]` 保证内存布局
    - LpmKeyV4 包含 prefix_len: u32 和 addr: u32（网络字节序）
    - RateLimitConfig 包含 rate: u64（字节/秒）和 burst: u64（字节）
    - TokenBucketState 包含 tokens: u64 和 last_refill_ns: u64
    - 实现令牌桶纯函数逻辑：refill_tokens() 和 process_packet()，供 eBPF 和测试共用
    - _需求：2.1, 2.2, 2.4, 2.5, 2.6, 5.4, 5.5, 7.4_

  - [x] 2.2 编写令牌消耗决策属性测试
    - **属性 1：令牌消耗决策正确性**
    - **验证需求：2.2, 2.3**

  - [x] 2.3 编写令牌补充计算属性测试
    - **属性 2：令牌补充计算正确性**
    - **验证需求：2.4, 2.6**

  - [x] 2.4 编写令牌数量不变量属性测试
    - **属性 3：令牌数量不变量**
    - **验证需求：2.6**

- [x] 3. 检查点 - 确保 qos-common 编译通过且测试通过
  - 确保所有测试通过，如有问题请询问用户。

- [x] 4. 实现 qos-ebpf TC Ingress 程序
  - [x] 4.1 在 `qos-ebpf/src/main.rs` 中实现 TC ingress classifier
    - 使用 `#![no_std]`、`#![no_main]` 和 aya-ebpf 宏
    - 定义 RULES（LpmTrie<LpmKeyV4, RateLimitConfig>）和 TOKEN_STATES（PerCpuHashMap<u32, TokenBucketState>）两个 BPF Map
    - 实现 `#[classifier] fn tc_ingress(ctx: TcContext) -> i32` 入口函数
    - 解析以太网帧头，检查是否为 IPv4（EtherType 0x0800），非 IPv4 直接放行
    - 解析 IPv4 头，提取源 IP 地址和数据包总长度
    - 使用源 IP 查询 LPM Trie，未匹配则放行
    - 匹配后读取 Per-CPU Hash Map 中的令牌桶状态（不存在则初始化）
    - 调用 qos-common 中的令牌桶逻辑计算补充和消耗
    - 返回 TC_ACT_PIPE（放行）或 TC_ACT_SHOT（丢弃）
    - 添加 `#[panic_handler]` 实现
    - _需求：1.1, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3, 3.4, 3.5, 5.1, 5.2, 5.3, 5.4, 5.5_

- [x] 5. 检查点 - 确保 qos-ebpf 编译通过
  - 使用 `cargo build` 在 qos crate 下触发 aya-build 编译 eBPF 程序，确保编译无错误。如有问题请询问用户。

- [x] 6. 实现用户空间 JSON 协议和 CIDR 解析
  - [x] 6.1 在 `qos/src/main.rs` 中定义 Request、Response、RuleInfo 数据结构和 CIDR 解析函数
    - 定义 Request 枚举（Add、Delete、List），使用 `#[serde(tag = "command")]` 标签式反序列化
    - 定义 Response 结构体（status、data、message 字段）
    - 定义 RuleInfo 结构体（ip、rate、burst 字段）
    - 实现 `parse_cidr(s: &str) -> Result<LpmKeyV4>` 函数，解析 CIDR 字符串为 LpmKeyV4
    - 实现 `format_cidr(key: &LpmKeyV4) -> String` 函数，将 LpmKeyV4 格式化为 CIDR 字符串
    - _需求：4.3, 4.4, 4.7, 4.8_

  - [x] 6.2 编写 CIDR 解析属性测试
    - **属性 4：CIDR 字符串解析正确性**
    - **验证需求：4.4, 3.1, 3.2**

  - [x] 6.3 编写 JSON 序列化往返属性测试
    - **属性 6：JSON 序列化往返**
    - **验证需求：4.8**

  - [x] 6.4 编写无效命令错误处理属性测试
    - **属性 7：无效命令错误处理**
    - **验证需求：4.7**

- [x] 7. 实现 BPF Map 管理器
  - [x] 7.1 在 `qos/src/map_manager.rs` 中实现 MapManager 结构体
    - 封装 aya 的 LpmTrie 和 PerCpuHashMap 引用
    - 实现 `add_rule(cidr: &str, rate: u64, burst: u64) -> Result<()>`：解析 CIDR，写入 LPM Trie
    - 实现 `delete_rule(cidr: &str) -> Result<()>`：解析 CIDR，从 LPM Trie 删除
    - 实现 `list_rules() -> Result<Vec<RuleInfo>>`：遍历 LPM Trie 返回所有规则
    - 处理 Map 容量满、key 不存在等错误场景
    - _需求：4.4, 4.5, 4.6, 5.1, 5.2, 5.3_

  - [x] 7.2 编写规则管理一致性属性测试
    - **属性 5：规则管理一致性**
    - **验证需求：4.5, 4.6**

- [x] 8. 实现 UDS 服务
  - [x] 8.1 在 `qos/src/uds.rs` 中实现 Unix Domain Socket 服务
    - 使用 tokio 的 UnixListener 在指定路径创建 UDS 并监听
    - 启动时若 socket 文件已存在则先删除
    - 接受客户端连接，按行读取 JSON 请求
    - 反序列化为 Request 枚举，调用 MapManager 执行对应操作
    - 构造 Response 并序列化为 JSON 返回给客户端
    - 处理 JSON 解析失败、未知命令、CIDR 格式无效、rate/burst 为 0 等错误
    - 客户端断开时记录日志并继续监听
    - _需求：4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8_

  - [x] 8.2 编写 UDS 服务单元测试
    - 测试各命令的请求解析和响应生成
    - 测试错误场景（无效 JSON、未知命令、无效 CIDR、rate/burst 为 0）
    - _需求：4.7, 4.8_

- [x] 9. 实现主程序入口和信号处理
  - [x] 9.1 在 `qos/src/main.rs` 中实现 CLI 解析、eBPF 加载和主循环
    - 使用 clap 定义 `--iface`（必填）和 `--socket-path`（默认 `/var/run/qos.sock`）参数
    - 初始化 env_logger 日志
    - 启动时输出当前配置的网络接口名称和 Socket 路径
    - 使用 aya 加载 eBPF 字节码（通过 `include_bytes_aligned!` 嵌入）
    - 添加 clsact qdisc 到指定接口（忽略已存在错误）
    - 将 TC ingress 程序挂载到指定网络接口
    - 获取 BPF Map 引用，创建 MapManager
    - 启动 UDS 服务
    - 使用 tokio::signal 监听 SIGINT/SIGTERM，触发优雅退出
    - 退出时删除 socket 文件、卸载 eBPF 程序
    - 处理权限不足、接口不存在等启动错误
    - _需求：1.1, 1.2, 1.3, 1.4, 6.1, 6.2, 6.3, 6.4_

  - [x] 9.2 编写 CLI 解析单元测试
    - 测试 `--iface` 必填验证
    - 测试 `--socket-path` 默认值
    - 测试无效参数处理
    - _需求：6.1, 6.2, 6.3_

- [x] 10. 最终检查点 - 确保所有代码编译通过且测试通过
  - 确保所有测试通过，如有问题请询问用户。

## 备注

- 标记 `*` 的任务为可选任务，可跳过以加速 MVP 开发
- 每个任务引用了具体的需求编号以确保可追溯性
- 检查点任务确保增量验证
- 属性测试使用 proptest 库验证通用正确性属性
- 单元测试验证具体示例和边界条件
- eBPF 程序的完整集成测试需要 Linux 环境和 root 权限，不在本任务列表范围内
