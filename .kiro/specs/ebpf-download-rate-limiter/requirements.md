# 需求文档

## 简介

本项目实现一个基于 aya 框架的 eBPF 下载限速器（QoS）。系统通过 eBPF TC（Traffic Control）程序挂载到网络接口，对指定 IP 地址或 IP 段（CIDR）的入站流量进行下载速度限制。用户空间控制面通过 Unix Domain Socket 接收管理指令，支持动态添加、删除和查询限速规则。限速算法采用 Token Bucket（令牌桶）实现平滑的流量控制。

## 术语表

- **Rate_Limiter**: 基于 aya 框架的 eBPF 下载限速系统，包含用户空间控制面和内核空间 eBPF 数据面
- **Control_Plane**: 运行在用户空间的 Rust 程序，负责加载 eBPF 程序、管理限速规则、监听 Unix Domain Socket 指令
- **Data_Plane**: 运行在内核空间的 eBPF TC 程序，负责对入站数据包执行令牌桶限速逻辑
- **UDS_Server**: Unix Domain Socket 服务端，监听并处理用户发送的限速管理请求
- **Token_Bucket**: 令牌桶算法实例，用于控制特定 IP 或 IP 段的下载速率
- **Rule**: 一条限速规则，包含目标 IP 地址或 CIDR 网段以及对应的速率限制参数
- **CIDR**: 无类别域间路由表示法，用于表示 IP 地址段（如 192.168.1.0/24）
- **BPF_Map**: eBPF Map 数据结构，用于用户空间与内核空间之间共享限速规则和令牌桶状态

## 需求

### 需求 1：eBPF TC 程序加载与挂载

**用户故事：** 作为系统管理员，我希望 Rate_Limiter 能将 eBPF TC 程序加载并挂载到指定网络接口，以便对入站流量进行限速控制。

#### 验收标准

1. WHEN Control_Plane 启动时，THE Rate_Limiter SHALL 将 Data_Plane eBPF 程序加载到内核并挂载到指定网络接口的 TC ingress 钩子上
2. WHEN Control_Plane 正常退出时，THE Rate_Limiter SHALL 从网络接口卸载 eBPF TC 程序并释放相关内核资源
3. IF eBPF 程序加载失败（如权限不足或内核不支持），THEN THE Rate_Limiter SHALL 输出明确的错误信息并以非零退出码终止
4. THE Rate_Limiter SHALL 通过命令行参数指定要挂载的网络接口名称

### 需求 2：令牌桶限速算法

**用户故事：** 作为系统管理员，我希望系统使用令牌桶算法对流量进行限速，以便实现平滑的下载速率控制。

#### 验收标准

1. THE Data_Plane SHALL 为每条 Rule 维护一个独立的 Token_Bucket 实例
2. WHEN 一个入站数据包匹配某条 Rule 时，THE Data_Plane SHALL 从对应的 Token_Bucket 中扣除与数据包大小相等的令牌数
3. IF Token_Bucket 中的可用令牌不足以容纳当前数据包，THEN THE Data_Plane SHALL 丢弃该数据包
4. WHILE Token_Bucket 未满时，THE Data_Plane SHALL 按照 Rule 中指定的速率持续补充令牌
5. THE Token_Bucket SHALL 支持配置速率（字节/秒）和突发容量（字节）两个参数
6. FOR ALL 有效的 Token_Bucket 配置，令牌数量在任意时刻 SHALL 不超过突发容量上限

### 需求 3：IP 地址与 CIDR 网段匹配

**用户故事：** 作为系统管理员，我希望能针对特定 IP 地址或 IP 段设置限速规则，以便精确控制目标流量。

#### 验收标准

1. THE Data_Plane SHALL 支持对单个 IPv4 源地址（如 10.0.0.1）进行匹配
2. THE Data_Plane SHALL 支持对 CIDR 格式的 IPv4 网段（如 192.168.1.0/24）进行匹配
3. WHEN 一个入站数据包的源 IP 地址匹配多条 Rule 时，THE Data_Plane SHALL 应用最长前缀匹配（最精确匹配）的 Rule
4. WHEN 一个入站数据包的源 IP 地址未匹配任何 Rule 时，THE Data_Plane SHALL 放行该数据包不做限速
5. THE Rate_Limiter SHALL 使用 BPF_Map（LPM Trie 类型）存储 IP/CIDR 到限速规则的映射关系

### 需求 4：Unix Domain Socket 控制接口

**用户故事：** 作为系统管理员，我希望通过 Unix Domain Socket 发送指令来管理限速规则，以便在运行时动态调整限速策略。

#### 验收标准

1. WHEN Control_Plane 启动时，THE UDS_Server SHALL 在指定路径创建 Unix Domain Socket 并开始监听连接
2. WHEN Control_Plane 正常退出时，THE UDS_Server SHALL 关闭监听并删除 Socket 文件
3. THE UDS_Server SHALL 支持以下管理命令：添加限速规则（add）、删除限速规则（delete）、列出当前所有规则（list）
4. WHEN 收到 add 命令时，THE UDS_Server SHALL 解析目标 IP/CIDR、速率（字节/秒）和突发容量参数，并将 Rule 写入 BPF_Map
5. WHEN 收到 delete 命令时，THE UDS_Server SHALL 从 BPF_Map 中移除指定 IP/CIDR 对应的 Rule
6. WHEN 收到 list 命令时，THE UDS_Server SHALL 返回当前所有活跃 Rule 的 IP/CIDR、速率和突发容量信息
7. IF 收到格式错误或无法识别的命令，THEN THE UDS_Server SHALL 返回明确的错误描述信息
8. THE UDS_Server SHALL 使用 JSON 格式进行请求和响应的序列化与反序列化

### 需求 5：BPF Map 数据共享

**用户故事：** 作为系统管理员，我希望用户空间的规则变更能实时反映到内核空间的限速行为，以便规则生效无需重启服务。

#### 验收标准

1. THE Rate_Limiter SHALL 使用 BPF_Map 在 Control_Plane 和 Data_Plane 之间共享限速规则数据
2. WHEN Control_Plane 向 BPF_Map 写入新 Rule 时，THE Data_Plane SHALL 在下一个数据包处理周期内使用更新后的 Rule
3. WHEN Control_Plane 从 BPF_Map 删除 Rule 时，THE Data_Plane SHALL 停止对该 Rule 对应的 IP/CIDR 进行限速
4. THE Rate_Limiter SHALL 使用 LPM Trie 类型的 BPF_Map 存储限速规则，以支持最长前缀匹配
5. THE Rate_Limiter SHALL 使用 Per-CPU Array 或 Hash 类型的 BPF_Map 存储 Token_Bucket 状态，以减少多核竞争

### 需求 6：命令行接口

**用户故事：** 作为系统管理员，我希望通过命令行参数配置 Rate_Limiter 的运行参数，以便灵活部署。

#### 验收标准

1. THE Rate_Limiter SHALL 支持通过命令行参数 `--iface` 指定要挂载 eBPF 程序的网络接口名称
2. THE Rate_Limiter SHALL 支持通过命令行参数 `--socket-path` 指定 Unix Domain Socket 的监听路径，默认值为 `/var/run/qos.sock`
3. IF 指定的网络接口不存在，THEN THE Rate_Limiter SHALL 输出明确的错误信息并以非零退出码终止
4. THE Rate_Limiter SHALL 在启动时输出当前配置的网络接口名称和 Socket 路径信息

### 需求 7：构建目标与项目结构

**用户故事：** 作为开发者，我希望项目能正确构建为 x86_64 Linux 目标，并且 eBPF 程序和用户空间程序的构建流程清晰分离。

#### 验收标准

1. THE Rate_Limiter SHALL 以 x86_64-unknown-linux-gnu 为构建目标
2. THE Rate_Limiter SHALL 将项目组织为 workspace 结构，包含用户空间程序 crate 和 eBPF 程序 crate
3. THE Rate_Limiter SHALL 将 eBPF 程序 crate 的构建目标设置为 bpfel-unknown-none（小端 eBPF 字节码）
4. THE Rate_Limiter SHALL 提供共享 crate 用于在用户空间和 eBPF 程序之间共享数据结构定义（如 BPF_Map 的 key/value 类型）
5. THE Rate_Limiter SHALL 使用 aya-build 在构建脚本中编译 eBPF 程序并将字节码嵌入用户空间二进制文件

