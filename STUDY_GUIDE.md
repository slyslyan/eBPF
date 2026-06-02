# eBPF-AutoHeal — 面试学习指南

> 目标：让你彻底理解 eBPF 无侵入可观测与自愈平台，面试时任何问题都能对答如流。
>
> 适用岗位：SRE / 后端开发 / 可观测性 / 基础设施
>
> 本文档是循序渐进的，建议按章节顺序阅读，配合源码一起看。

---

## 目录

1. [项目概述](#1-项目概述)
2. [技术栈详解](#2-技术栈详解)
3. [eBPF 基础概念（面试必知）](#3-ebpf-基础概念面试必知)
4. [项目结构与架构](#4-项目结构与架构)
5. [核心流程详解](#5-核心流程详解)
6. [重要文件清单与代码解读](#6-重要文件清单与代码解读)
7. [核心算法深度解析](#7-核心算法深度解析)
8. [实战踩坑记录](#8-实战踩坑记录)
9. [面试常见问题](#9-面试常见问题)
10. [SRE 专项面试准备](#10-sre-专项面试准备)
11. [快速复习卡片](#11-快速复习卡片)

---

## 1. 项目概述

**eBPF-AutoHeal** 是一个基于 eBPF 的零侵入微服务可观测与自愈平台。它在内核态捕获所有 TCP 通信，无需修改任何代码，即可实现完整的 SRE 闭环：

**发现 → 定位 → 自愈 → 现场保全 → 通知**

### 核心功能

| 功能 | 说明 |
|------|------|
| 零侵入采集 | eBPF kprobe 挂载 `tcp_sendmsg`，自动提取四元组 + 延迟 |
| 连接生命周期 | kprobe `tcp_connect` + `tcp_close` 跟踪连接持续时间 |
| 自适应阈值 | 滑动窗口 P95 + EMA 基线，避免固定阈值误报 |
| 多维度异常检测 | 延迟比率 + 错误率 + 调用量骤降三因子综合评分 |
| 反向随机游走 | 在反向图上执行 PageRank 变体，定位级联故障根因 |
| 故障集群分组 | 分数相近的嫌疑节点归为一组，提示共享基础设施 |
| 历史模式匹配 | Jaccard 相似度比较历史故障，推荐处理方案 |
| 内核级自愈 | eBPF TC 100% 丢包限流，受保护 IP 白名单 |
| K8s Pod 隔离 | client-go 查找嫌疑 Pod 并重启 |
| HTTP/gRPC 解析 | uprobe 挂载 Go 运行时函数，解析到方法/路径/状态码 |
| 故障现场保全 | CPU 火焰图、内存火焰图、Goroutine dump、tcpdump 抓包 |
| Prometheus 指标 | 延迟分布、异常分数、自愈事件、探针自监控 |
| 飞书/钉钉通知 | 根因分析摘要发送到 IM 群 |

### 核心数据流

```
eBPF kprobe → Ring Buffer → Go 用户态 → ServiceGraph
  → 异常检测 (P95 + EMA) → 根因分析 (PageRank)
  → 自愈 (TC丢包 / K8s重启) → 现场保全 (火焰图/tcpdump)
  → 飞书通知
```

---

## 2. 技术栈详解

### 内核层

| 技术 | 用途 | 面试关键点 |
|------|------|-----------|
| eBPF | 内核沙箱程序 | 验证器（安全）、JIT 编译（性能）、CO-RE（可移植） |
| kprobe/kretprobe | 动态内核探针 | 入口记录时间 → 出口计算延迟，四元组读取 |
| TC (Traffic Control) | 网络包处理 | ingress 方向丢包，BPF map 共享规则 |
| uprobe | 用户态探针 | Go ABI 寄存器传参（RAX/RBX/RCX），非标准 x86_64 |
| CO-RE (Compile Once, Run Everywhere) | 内核兼容 | BTF 信息 + `vmlinux.h`，一次编译多内核运行 |
| BPF Map | 内核-用户态共享 | `tc_drop_ips` map 存储待丢包 IP 列表 |
| Ring Buffer | 内核-用户态事件通道 | 替代 eBPF Perf Buffer，更高效的有界缓冲区 |

### 用户态（Go）

| 技术 | 用途 | 面试关键点 |
|------|------|-----------|
| cilium/ebpf | eBPF Go 库 | bpf2go 生成绑定、link.Kprobe、ringbuf.Reader |
| bpf2go | C→Go 绑定生成 | `go:generate` 指令编译 C 代码生成 `.go` 文件 |
| Prometheus client_golang | 指标暴露 | Counter/Gauge/Histogram 三种指标类型 |
| client-go | K8s API | Pod List/Delete 实现隔离 |
| go tool pprof | 火焰图生成 | profile → SVG 转换 |

### 算法

| 算法 | 用途 | 复杂度 |
|------|------|--------|
| EMA (指数移动平均) | 动态延迟基线 | O(1) 每条边 |
| 滑动窗口 P95 | 自适应阈值 | O(N log N) 窗口内排序 |
| 反向随机游走 (PageRank 变体) | 根因传播 | O(I × E) I=迭代次数, E=边数 |
| Jaccard 相似度 | 历史模式匹配 | O(N+M) 集合运算 |
| Top-K 聚类 | 故障分组 | O(K log K) 排序 |

---

## 3. eBPF 基础概念（面试必知）

### 3.1 什么是 eBPF？

eBPF（extended Berkeley Packet Filter）是一种在内核中运行沙箱程序的技术。它允许用户在不需要修改内核源码或加载内核模块的情况下，安全地扩展内核功能。

**传统方式 vs eBPF：**
- 内核模块：危险（一个 bug 就能让整个系统崩溃）
- eBPF：安全（验证器检查所有程序，拒绝危险操作）

### 3.2 四种探针类型

| 类型 | 挂载点 | 项目中的用途 |
|------|--------|-------------|
| kprobe | 内核函数入口 | `tcp_sendmsg` 入口记录四元组和时间戳 |
| kretprobe | 内核函数返回 | `tcp_sendmsg` 返回计算延迟 |
| TC | 网络数据包入口 | ingress 方向丢包 |
| uprobe | 用户态函数 | Go HTTP/gRPC 函数参数读取 |

### 3.3 eBPF 关键概念

```
eBPF 程序生命周期：
1. 编写 C 代码（如 net_trace.c）
2. clang/LLVM 编译为 BPF 字节码
3. 通过 bpf() syscall 加载到内核
4. 内核验证器检查安全性（循环次数、指针访问等）
5. JIT 编译为机器码
6. 挂载到探针点（kprobe/TC/uprobe）
7. 事件触发 → 执行 eBPF 程序 → 输出到 Ring Buffer
8. 用户态读取 Ring Buffer → 处理事件
```

### 3.4 CO-RE (Compile Once, Run Everywhere)

```
问题：不同内核版本的结构体字段偏移不同，直接访问会出错。
解决：BPF CO-RE，通过 BPF_CORE_READ 宏和 BTF 信息，
在加载时自动重定位字段偏移。

相关文件：
  bpf/vmlinux.h — BTF 导出的内核类型定义
  BPF_CORE_READ_INTO — 安全读取内核结构体字段
  SEC("kprobe/tcp_sendmsg") — 探针挂载点声明
```

### 3.5 Ring Buffer vs Perf Buffer

```
Perf Buffer 的缺点：
  - 每个 CPU 一个缓冲区 → 事件乱序
  - 需要处理 CPU 热插拔
  - 丢失事件时只能统计丢了多少

Ring Buffer 的优势：
  - 全局有界缓冲区
  - 事件保序（FIFO）
  - 内存开销可预测
  - 支持数据预留/提交（reserve/submit）模式
```

---

## 4. 项目结构与架构

### 4.1 目录结构

```
ebpf-autoheal/
├── bpf/                           ★ eBPF C 源码（重点）
│   ├── net_trace.c                # TCP 延迟探针（kprobe/tcp_sendmsg）
│   ├── tcp_conntrack.c            # 连接生命周期（kprobe/tcp_connect + tcp_close）
│   ├── tc_drop.c                  # TC 入口丢包程序
│   ├── http_probe.c               # HTTP/gRPC uprobe 程序
│   └── vmlinux.h                  # 内核类型定义（CO-RE 必需）
│
├── cmd/tracer/                    ★ Go 用户态（重点）
│   ├── main.go                    # 入口，eBPF 加载，事件循环
│   ├── config.go                  # 配置系统（13+ 环境变量）
│   ├── types.go                   # 类型定义（Ring Buffer 事件结构体、图结构）
│   ├── graph.go                   # 服务拓扑图（节点、边、EMA、P95）
│   ├── analysis.go                # ★ 根因分析引擎（算法核心）
│   ├── mitigation.go              # 自愈操作（TC/K8s/火焰图/通知）
│   ├── resolver.go                # cgroup 服务身份解析
│   ├── http_probe.go              # HTTP/gRPC 事件消费者
│   ├── tc_drop.go                 # eBPF TC 程序管理
│   ├── metrics.go                 # Prometheus 指标注册
│   ├── metrics_helper.go          # 标签基数保护
│   ├── analysis_test.go           # 单元测试
│   ├── tracer_bpfel.go            # [生成] net_trace 绑定
│   ├── tc_drop_bpfel.go           # [生成] tc_drop 绑定
│   ├── http_probe_bpfel.go        # [生成] http_probe 绑定
│   └── tcp_conntrack_bpfel.go     # [生成] tcp_conntrack 绑定
│
├── deploy/
│   └── ebpf-tracer.yaml           # K8s DaemonSet 部署
├── Dockerfile.agent               # 容器构建
└── project-log.md                 # 开发日志（中文，含详细踩坑记录）
```

### 4.2 整体架构

```
┌──────────────────────────────────────────────────┐
│                 内核空间 (Kernel)                   │
│                                                    │
│  kprobe/tcp_sendmsg ──→ [eBPF Prog] ──→ Ring Buffer
│       │ (入口记录时间)        │                     │
│  kretprobe/tcp_sendmsg ──→ [eBPF Prog] ──→ Ring Buffer
│       │ (返回计算延迟)        │                     │
│  kprobe/tcp_connect ──→ [eBPF Conntrack] ──→ connRingBuf
│  kprobe/tcp_close ──→     (持续时间)         │      │
│       │                                       │      │
│  TC Ingress ──→ [tc_drop eBPF] ←── tc_drop_ips map
│       │          (匹配则 TC_ACT_SHOT)       ↑      │
│       │                                     │      │
│  uprobe/Go HTTP ──→ [http_probe eBPF] ──→ httpRingBuf
│                                                    │
└──────────────────┬─────────────────────────────────┘
                   │ ringbuf.Read()
┌──────────────────▼─────────────────────────────────┐
│               用户空间 (Userspace Go)                 │
│                                                    │
│  ┌─────────┐  main loop: 解析 → graph.AddCall()    │
│  │ Service  │  → PrintStats (定时)                   │
│  │  Graph   │  → AnalyzeRootCause (定时)             │
│  └────┬────┘                                        │
│       │                                              │
│  ┌────▼────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ Root    │  │ Fault    │  │ History           │   │
│  │ Cause   │──▶ Cluster  │──▶ Pattern           │   │
│  │ (Page   │  │ (Top-K)  │  │ (Jaccard)         │   │
│  │ Rank)   │  └──────────┘  └───────────────────┘   │
│  └────┬────┘                                         │
│       ▼  (performMitigation)                         │
│  ┌────────────────────────────────────────────┐      │
│  │  eBPF TC → K8s restart → FlameGraph → Alert│      │
│  └────────────────────────────────────────────┘      │
│                                                    │
│  ┌────────────────────────────────────────────┐      │
│  │  Prometheus :2112/metrics                  │      │
│  │  Health     :2112/healthz                  │      │
│  └────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────┘
```

### 4.3 一次完整的自愈闭环

```
用户启动探针
    │
    ▼
eBPF 程序加载到内核（kprobe/tcp_sendmsg）
    │
    ▼
TCP 通信发生 → eBPF 捕获四元组+延迟 → Ring Buffer
    │
    ▼
Go 主循环读取事件 → graph.AddCall() 更新拓扑
    │
    ▼
每 15s → AnalyzeRootCause()
    ├─ 自适应阈值：P95 × 1.2（不被持续性高延迟误报）
    ├─ 调用量骤降：检测 QPS 从 100 → 0（服务挂了）
    ├─ 反向随机游走：传播嫌疑找到根因
    ├─ 故障集群：分数相近的节点归为一组
    └─ 历史匹配：和上次故障类似？给建议
    │
    ▼ 发现嫌疑节点 → performMitigation()
    ├─ eBPF TC 丢包（内核态，微秒级）
    ├─ K8s 查找 Pod → 删除重启
    ├─ 采集 CPU/内存火焰图
    ├─ 采集 Goroutine/线程 dump
    ├─ tcpdump 抓包
    └─ 飞书通知
```

---

## 5. 核心流程详解

### 5.1 eBPF 事件采集流程

```
bpf/net_trace.c (C 代码)
    │
    ├─ SEC("kprobe/tcp_sendmsg")  ← 入口探针
    │   ├─ BPF_CORE_READ_INTO 读取 struct sock *sk:
    │   │   └─ sk->__sk_common.skc_daddr  (目标 IP)
    │   │   └─ sk->__sk_common.skc_rcv_saddr (源 IP)
    │   │   └─ sk->__sk_common.skc_dport  (目标端口)
    │   │   └─ sk->__sk_common.skc_num    (源端口)
    │   │   └─ sk->__sk_common.skc_family (AF_INET/AF_INET6)
    │   ├─ 获取 PID 和 comm（进程名）
    │   ├─ 读取 ktime 作为起始时间戳
    │   └─ 存入 BPF map: key=pid, value=四元组+时间戳
    │
    ├─ SEC("kretprobe/tcp_sendmsg")  ← 返回探针
    │   ├─ 从 BPF map 取出入口记录
    │   ├─ Delta = 当前时间 - 入口时间
    │   ├─ 填充 net_event 结构体（48 字节）
    │   └─ ringbuf_submit() 发送到用户态
    │
    └─ Ring Buffer → Go 用户态 → main 循环解析

Go 端（main.go）：
    binary.Read(record.RawSample, LittleEndian, &raw)  // 解析 48 字节
    srcService = resolver.Resolve(pid, comm)            // 解析服务名
    graph.AddCall(srcService, dstService, delayMs, isError)  // 更新图
```

### 5.2 延迟数据是怎么算的？

```
tcp_sendmsg 延迟 ≠ 网络 RTT

kprobe 入口:
  time_start = bpf_ktime_get_ns()
  map[pid] = {saddr, daddr, sport, dport, time_start}

  → 用户进程调用 tcp_sendmsg（将数据写入 TCP 缓冲区）
  → 内核协议栈处理（拥塞控制、分段...）
  → 数据放入发送队列

kretprobe 返回:
  record = map[pid]
  delta = bpf_ktime_get_ns() - record.time_start

  delta 包含：数据从用户态拷贝到内核态缓冲区的时间
  如果 TCP 窗口满，还会包含等待窗口打开的时间

注意：这个延迟是"发送耗时"，不是"请求-响应 RTT"。
RTT 可以从 tcp_conntrack 的连接持续时间推算。
```

### 5.3 服务身份解析流程

```
eBPF 捕获: PID=12345 comm="curl"
    │
    ▼
resolver.Resolve(pid=12345, comm="curl")
    │
    ├─ 缓存命中 → 直接返回（30 秒 TTL）
    │
    └─ 缓存未命中 → 慢速路径：
        │
        ├─ 第 1 步: /proc/12345/cgroup
        │   读取 cgroup 路径 → 提取 Pod UID
        │   格式: /kubepods/burstable/pod<uid>/<container-id>
        │   → 如果启用了 K8s: List Pods by UID → 返回 Pod 名
        │   → 回退: "pod-<uid>"
        │
        ├─ 第 2 步: /proc/12345/cmdline
        │   读取可执行文件路径 → 取最后一部分
        │   /usr/bin/curl → "curl"
        │
        └─ 第 3 步: 回退到 comm
            "curl"（eBPF 原始数据）
```

### 5.4 异常检测算法

```
每次分析周期（默认 15 秒）：

对每条边 e:
  1. 延迟异常检测
     threshold = max(e.P95 × 1.2, 10ms)  // 自适应阈值
     latRatio = e.AvgLat / threshold
     if latRatio < 1.0: latRatio = 0      // 在阈值内 = 正常

  2. 错误率因子
     errorFactor = 1 + e.Errors / e.Count

  3. 调用量骤降检测
     deltaCount = e.Count - e.LastCount
     currentQPS = deltaCount / 15s
     CallEMA = α × currentQPS + (1-α) × CallEMA
     if currentQPS < CallEMA × 0.3:
       CallAnomaly = 1 + (CallEMA - currentQPS) / CallEMA

  4. 综合分数
     AnomalyScore = latRatio × errorFactor + CallAnomaly × 2.0
```

### 5.5 反向随机游走（面试重点）

```
输入：有异常的边的目标节点（种子）
输出：每个节点的嫌疑分数

类比：在犯罪现场发现指纹（异常），侦探沿着线索反向追踪
可疑人物。每一步都有概率回到现场重新找线索（防止跟丢）。

算法步骤：
  1. 初始化：种子节点概率 = 异常分数 / 总异常分数
  2. 迭代（最多 50 轮）：
     对每个节点：
       - 以 15% 概率回到种子（重启）
       - 以 85% 概率沿入边反向传播到调用方
     传播时按入边的异常分数加权（异常越高的边嫌疑越大）
  3. 收敛后返回最终概率分布

为什么工作？
  - 如果服务 A 调用 B，B 出现异常，B 的入边异常分数高
  - 反向随机游走从 B 向上游传播到 A
  - 如果 A 还调用了 C、D，且它们都异常，A 的嫌疑更高
  - 这与 "被多个异常服务调用的服务更可能是根因" 直觉一致
```

---

## 6. 重要文件清单与代码解读

### 6.1 必须读懂（面试高频）

| # | 文件 | 重要性 | 为什么重要 |
|---|------|--------|-----------|
| 1 | `cmd/tracer/main.go` | ⭐⭐⭐⭐⭐ | 程序入口，eBPF 加载，Ring Buffer 主循环 |
| 2 | `bpf/net_trace.c` | ⭐⭐⭐⭐⭐ | eBPF C 代码，TCP 延迟捕获逻辑 |
| 3 | `cmd/tracer/analysis.go` | ⭐⭐⭐⭐⭐ | 根因分析引擎核心算法 |
| 4 | `cmd/tracer/graph.go` | ⭐⭐⭐⭐⭐ | 服务拓扑图 + EMA + P95 |
| 5 | `cmd/tracer/types.go` | ⭐⭐⭐⭐ | Ring Buffer 事件结构体定义 |
| 6 | `cmd/tracer/mitigation.go` | ⭐⭐⭐⭐ | 自愈操作（TC/K8s/火焰图/通知） |

### 6.2 建议读懂

| # | 文件 | 为什么重要 |
|---|------|-----------|
| 7 | `cmd/tracer/config.go` | 配置系统 + 冷却期管理 |
| 8 | `cmd/tracer/resolver.go` | cgroup 服务身份解析 |
| 9 | `cmd/tracer/http_probe.go` | HTTP/gRPC uprobe 消费 |
| 10 | `cmd/tracer/tc_drop.go` | eBPF TC 程序管理 |
| 11 | `cmd/tracer/metrics.go` | Prometheus 指标定义 |
| 12 | `cmd/tracer/metrics_helper.go` | 标签基数保护 |

### 6.3 核心代码逐行解读

#### cmd/tracer/main.go — 启动入口

```go
// main 启动流程：
//
// 1. initConfig()                  — 加载配置
// 2. initProtectedIPs()            — 受保护 IP（防误杀）
// 3. initK8sClient()              — K8s 客户端
// 4. 加载 4 个 eBPF 程序：
//    ├─ kprobe tcp_sendmsg       → TCP 延迟
//    ├─ kprobe tcp_connect/close → 连接跟踪
//    ├─ TC ingress               → 内核丢包
//    └─ uprobe HTTP/gRPC         → 协议解析
// 5. HTTP 服务 :2112（metrics + healthz）
// 6. 定时器：拓扑打印 / 根因分析 / 冷却清理
// 7. 主循环：ringbuf.Read() → 解析 → graph.AddCall()

// 关键代码：Ring Buffer 读取循环
for {
    record, err := rd.Read()           // 阻塞读取内核事件
    binary.Read( ..., &raw)             // 解析 48 字节二进制数据
    delayMs := float64(raw.Delta) / 1e6 // 纳秒转毫秒
    srcService := resolver.Resolve(pid, comm)  // 解析服务名
    graph.AddCall(src, dst, delayMs, isError)  // 更新拓扑
}
```

#### cmd/tracer/graph.go — 服务图核心

```go
// AddCall — 每次 eBPF 事件调用一次
func (g *ServiceGraph) AddCall(src, dst string, latencyMs float64, isError bool) {
    // 1. 创建或获取节点/边
    // 2. 更新统计：Count++, TotalLat += latency
    // 3. EMA 更新：EmaLat = α×AvgLat + (1-α)×EmaLat
    // 4. 滑动窗口：追加 → 超 30 个则移除最旧
    // 5. P95 计算：percentile(window, 95)
    // 6. 目标节点聚合：入边加权平均延迟
    // 7. Prometheus 指标更新（带标签基数保护）
}

// percentile — 线性插值百分位数
// 等价于 Excel 的 PERCENTILE 函数
func percentile(data []float64, p float64) float64 {
    sorted := sort(data)
    k := p/100 * (len-1)
    // k 不是整数时线性插值
}
```

#### cmd/tracer/analysis.go — 根因分析引擎

```go
// AnalyzeRootCause — 完整的根因分析流程
func (g *ServiceGraph) AnalyzeRootCause() []Suspicion {
    // 第 1 步：计算每条边的异常分数
    //   延迟因子 × 错误因子 + 调用量异常 × 权重

    // 第 2 步：反向随机游走（Fault Propagation Rank）
    //   seeds = {异常边.目标节点: 异常分数}
    //   迭代 50 轮：15% 概率重启，85% 概率沿入边反向传播

    // 第 3 步：故障集群分组
    //   分数差异 < 15% → 同一集群

    // 第 4 步：历史模式匹配
    //   Jaccard 相似度 > 0.6 → 给出建议
}
```

#### cmd/tracer/mitigation.go — 自愈操作

```go
// performMitigation — 对嫌疑节点执行自愈
func performMitigation(suspects []Suspicion) {
    // 1. 冷却期检查（同一节点 120 秒内不重复自愈）
    // 2. eBPF TC 限流（将 IP 写入 BPF map）
    //    回退：tc 命令丢包
    // 3. K8s Pod 查找并重启（client-go）
    // 4. 故障现场保全：
    //    ├─ CPU 火焰图（pprof profile + go tool pprof -svg）
    //    ├─ 内存火焰图（pprof heap）
    //    ├─ Goroutine dump
    //    ├─ 线程 dump
    //    └─ tcpdump 抓包
    // 5. 飞书通知
}
```

---

## 7. 核心算法深度解析

### 7.1 EMA（指数移动平均）

```
公式：EMAt = α × Valuet + (1-α) × EMAt-1

α=0.2 的含义：
  新值权重 20%，历史权重 80%
  大约 14 个数据点后，旧数据的影响降低到 5% 以下

为什么用 EMA 而不是简单平均？
  - 简单平均：所有历史数据权重相同，无法快速响应变化
  - EMA：指数衰减旧数据权重，更敏感于近期趋势
  - 实现简单：只需要记住一个值，不用存历史窗口

项目中 EMA 的应用：
  1. emaLat — 延迟基线
  2. CallEma — 调用速率基线
```

### 7.2 滑动窗口 P95

```
为什么用 P95 不是 P99 或平均值？
  - 平均值：容易被极端值拉偏（少数高延迟就拉高了平均）
  - P99：对 1% 的极端值太敏感，可能导致频繁误报
  - P95：恰到好处——忽略 5% 的噪声，对真实异常敏感

为什么不用固定阈值？
  不同服务的正常延迟差异很大：
  - Redis 查询：< 1ms
  - MySQL 查询：10-50ms
  - 外部 API：100-500ms
  固定 200ms 阈值会让 Redis 永远不触发，外部 API 永远在触发。
  P95 自适应：每个服务都有自己的阈值。
```

### 7.3 调用量骤降检测

```
场景：服务 A 调用 B，突然 A 挂了（或网络分区），B 的入站流量骤降。

旧方案（问题）：
  只看延迟 → B 的延迟正常（因为没请求了）→ 不认为 B 异常
  但实际上 B 出问题是因为 A 挂了，B 是受害者不是根因

本项目方案：
  监控每条边的 QPS 变化。
  如果当前 QPS 骤降到基线的 30% 以下 → 标记为异常。
  通过反向随机游走，从 B 向上游传播到 A → A 是根因。

这就是多维度异常检测的意义：
  只靠延迟不够，还要看调用量、错误率。
```

### 7.4 标签基数保护

```
问题：
  服务拓扑的边数 = N²（N 个服务互相调用）
  每条边都有 Prometheus 标签 {src, dst}
  如果 N=10000，就有 100M 个标签组合 → Prometheus OOM

解决：
  限制每个指标的最大标签组合数（默认 100）。
  超过上限的静默丢弃，不写入 Prometheus。

这是一个"优雅降级"的设计：宁愿丢掉一些数据，也不能搞垮监控系统。
```

---

## 8. 实战踩坑记录

### 坑 1: eBPF IPv6 双栈导致 IP 全 0

**现象：** TCP 四元组中源 IP 和目标 IP 为全 0。

**排查过程：**
1. Go 程序默认使用 `AF_INET6`（即使只监听 IPv4）
2. 在 IPv6 socket 中，IPv4 地址存储在 `skc_v6_rcv_saddr` 的最后 4 字节
3. 原来的 `skc_rcv_saddr` 字段为 0

**根因：** 内核 `struct sock_common` 中，IPv4-mapped-IPv6 地址需要特殊处理，直接读 `skc_rcv_saddr` 是错的。

**解决方案：** 在 eBPF C 代码中判断 `skc_family`：
- `AF_INET` (2)：读 `skc_rcv_saddr`
- `AF_INET6` (10)：读 `skc_v6_rcv_saddr` 的后 4 字节

### 坑 2: 字节序问题（IP 显示为 2.49.168.192）

**现象：** 期望的 IP `192.168.49.2` 显示为 `2.49.168.192`。

**排查过程：**
1. eBPF 从内核读取的 IP 是网络字节序（大端）
2. bpf2go 生成的 Go 绑定自动处理了字节序转换
3. 但 Ring Buffer 中的数据是原始二进制，不会自动转换

**根因：** Go 端使用 `binary.Read` 读取 Ring Buffer 时，需要明确指定字节序。如果不匹配，uint32 的高低字节会颠倒。

**解决方案：** Go 端统一使用 `binary.LittleEndian` 读取 eBPF Ring Buffer 事件。

### 坑 3: kretprobe 中读取 sk 参数为 0

**现象：** kretprobe 中读取 sock 指针得到 0。

**排查过程：**
1. kprobe 入口：`tcp_sendmsg(struct sock *sk, ...)` — sk 是第一个参数，在 RDI 寄存器
2. kretprobe 返回：函数上下文已销毁，寄存器已不是原来的值

**根因：** kretprobe 中无法直接从寄存器获取函数参数。

**解决方案：** kprobe/kretprobe 分离模式：
- kprobe 入口：将四元组和时间戳存入 BPF map（以 PID 为 key）
- kretprobe 返回：从 BPF map 取出数据，计算延迟，不读寄存器

### 坑 4: Go ABI 寄存器传参与 uprobe

**现象：** uprobe 挂载到 Go HTTP 函数后，读取的参数全为 0。

**排查过程：**
1. 标准 x86_64 ABI：参数在 RDI, RSI, RDX, RCX...
2. Go ABI：参数在 RAX, RBX, RCX...（Go 1.17+ 的寄存器传参约定）
3. 标准的 `PT_REGS_PARM1` 宏读的是 RDI，对 Go 程序是错的

**根因：** Go 的 ABI 与标准 System V ABI 不同，需要使用不同的寄存器读取方式。

**解决方案：** eBPF 程序中直接读 `ctx->ax`, `ctx->bx`, `ctx->cx`：
```c
// Go ABI: arg0 = RAX, arg1 = RBX, arg2 = RCX
uint64_t req_ptr = ctx->ax;  // 第一个参数：*conn.readRequest 的指针
```

### 坑 5: 自愈误杀 K8s 控制平面

**现象：** 自愈触发后，Minikube K8s 集群断连，kubectl 报 `no route to host`。

**排查过程：**
1. 查看被限流的 IP：发现 `192.168.49.2`（Minikube API server）被加入了 drop list
2. tc 限流导致 K8s API 不可达
3. 所有依赖 API server 的操作都失败

**根因：** 没有对 K8s 控制平面的 IP 做保护。

**解决方案：** 添加 `initProtectedIPs()`，将 `192.168.49.2` 加入白名单：
```go
func initProtectedIPs() {
    protectedIPs["127.0.0.1"] = true
    protectedIPs["::1"] = true
    protectedIPs["192.168.49.2"] = true // Minikube API server
}
```

### 坑 6: 调用量骤降检测始终为 0

**现象：** 即使停了所有请求，`CallAnomaly` 仍为 0，不触发检测。

**排查过程：**
1. 发现 `CallAnomaly` 计算用的是 `e.Count`（累计值）
2. 累计值只增不减，增量始终 >= 0（即使请求停了，Count 也不会变）
3. 预期是"当前 QPS 与历史基线比较"，但实际一直在用累计值

**根因：** 计算"当前 QPS"时直接用 `Count`，而不是 `Count - LastCount`。

**解决方案：** 增加 `LastCount` 字段，每次分析时计算增量：
```go
deltaCount := e.Count - e.LastCount
currentQPS := float64(deltaCount) / cfg.AnalysisWindowSec
e.LastCount = e.Count
```

---

## 9. 面试常见问题

### 9.1 eBPF 基础

**Q: eBPF 和内核模块有什么区别？为什么 eBPF 更安全？**

A: 内核模块是用户编写的 C 代码直接在内核中运行。一个空指针解引用就能导致整个系统崩溃。eBPF 在内核中有一个验证器（Verifier），在加载程序时会检查：
- 所有循环必须有界（防止死循环）
- 所有指针访问必须经过边界检查（防止越界）
- 不允许直接访问内核函数（必须通过 BPF helper）
- 程序大小限制在 100 万条指令内

所以 eBPF 更安全：验证器确保程序不会搞崩内核。

**Q: 什么是 CO-RE？为什么需要它？**

A: CO-RE = Compile Once, Run Everywhere。不同内核版本的结构体字段偏移不同（比如 `task_struct.comm` 在 5.10 和 6.8 中的偏移可能不同）。没有 CO-RE 的话，每个内核版本都要重新编译 eBPF 程序。CO-RE 通过 BTF 信息在加载时动态重定位字段偏移，实现"一次编译，到处运行"。

**Q: eBPF 程序的工作流程是怎样的？**

A: 编写 C 代码 → clang 编译为 BPF 字节码 → `bpf()` syscall 加载到内核 → 验证器检查安全性 → JIT 编译为机器码 → 挂载到探针点 → 事件触发时执行 → 通过 Ring Buffer/Map 与用户态通信。

### 9.2 项目设计

**Q: 为什么用 Ring Buffer 而不是 Perf Buffer？**

A: Ring Buffer 是 eBPF 的新一代事件传输机制。Perf Buffer 为每个 CPU 分配一个缓冲区，导致事件乱序、需要处理 CPU 热插拔。Ring Buffer 是全局有界缓冲区，事件保序、内存可预测，适用于高吞吐场景。本项目的 TCP 事件每秒可能数千个，Ring Buffer 更合适。

**Q: 怎么保证不误杀关键服务？**

A: 三层保护：
1. 受保护 IP 列表（initProtectedIPs）— localhost、K8s API server 等不会限流
2. 冷却期（120 秒）— 同一节点不会反复自愈
3. 自适应阈值（P95）— 对持续高延迟不触发（阈值会自动抬高）

**Q: 什么是"零侵入"？怎么做到的？**

A: 传统可观测方案需要在代码中集成 SDK（如 OpenTelemetry），或在部署时注入 Sidecar（如 Istio）。这带来的问题是：改代码、加依赖、性能开销。eBPF 通过在内核层面探针捕获 TCP 通信，不需要修改任何代码、不需要重启服务、不需要加 Sidecar。从内核层面获取数据，对应用完全透明。

**Q: 多维度异常分数是怎么组合的？为什么这么设计？**

A: 综合分数 = 延迟因子 × 错误因子 + 调用量异常因子 × 权重。三者的设计理由：
- **延迟因子**：最直接的异常信号，服务变慢是最常见的故障表现
- **错误因子**：放大异常——高延迟+高错误率同时出现时分数更高
- **调用量骤降**：检测静默故障——服务没变慢但突然没有流量了（可能上游挂了）

三个维度覆盖了"变慢"、"报错"、"消失"三种故障模式。

### 9.3 Go 和工程

**Q: 这个项目用到了哪些 Go 并发模式？**

A: ① goroutine（HTTP 服务、定时期、连接跟踪消费都在独立 goroutine 中运行）② channel（信号通知优雅关闭）③ sync.RWMutex（ServiceGraph 的读写锁，高频读取低频写入的场景）④ select + channel（tcpdump 超时控制）

**Q: 为什么要有标签基数保护？**

A: Prometheus 的标签组合数是 O(N²) 的。如果服务拓扑中有 1000 个端点，理论上就有百万级别的标签组合。这会导致 Prometheus 内存爆炸。保护策略是限制每个指标的最大标签组合数（默认 100），超出的静默丢弃。这是"优雅降级"——丢数据比搞崩监控系统好。

---

## 10. SRE 专项面试准备

### 10.1 这个项目展示的 SRE 能力

| SRE 领域 | 项目中的体现 |
|----------|-------------|
| 可观测性 (Observability) | eBPF 零侵入采集 + Prometheus 指标 + 火焰图 |
| 告警 (Alerting) | 自适应阈值 + 飞书通知 |
| 自愈 (Auto-healing) | TC 限流 + K8s Pod 重启 |
| 容量规划 | 关注点不在本项目，但 eBPF 数据可用于容量分析 |
| 故障排查 | 根因分析 + 故障现场保全 |
| 运维自动化 | DaemonSet 部署 + 配置驱动 |

### 10.2 常见 SRE 面试题用本项目回答

**Q: 服务变慢怎么排查？**

A: "我这项目的 eBPF 探针就是用来做这个的。首先从 Prometheus 看延迟分布，找到异常边。然后看异常分数最高的节点——反向随机游走算法已经帮我定位了根因。如果还不够，自愈时自动采集的火焰图和 goroutine dump 可以进一步分析。整个过程零侵入，不需要提前埋点。"

**Q: 怎么做无损发布？**

A: "本项目不直接处理这个，但 eBPF 可以在这个过程中发挥作用：探针能实时监控发布过程中的调用延迟和错误率变化，如果发现异常可以自动触发 TC 限流或回滚（通过 K8s API）。"

**Q: 监控系统的设计原则是什么？**

A: "从本项目的经验来看：① 分层采集（内核 eBPF + 应用指标 + 日志）② 自适应阈值（避免固定阈值误报）③ 自监控（探针自身的 events/errors 指标）④ 优雅降级（标签基数保护防止监控系统被拖垮）"

### 10.3 从运维角度看本项目

```
部署方式：
  开发环境：sudo ./ebpf-local（本地运行）
  生产环境：K8s DaemonSet（每个节点一个 Pod）

权限需求：
  - privileged: true（需要加载 eBPF 程序）
  - hostNetwork: true（访问宿主机网络接口）
  - hostPID: true（读取 /proc 解析 cgroup）

监控自身：
  - /healthz 端点（存活检查）
  - ebpf_agent_events_total（处理事件数）
  - ebpf_agent_errors_total（错误事件数）
  - ebpf_agent_up（是否运行中）

故障排查命令：
  查看日志: kubectl logs -n ebpf-system -l app=ebpf-tracer
  查看指标: curl <pod-ip>:2112/metrics
  检查健康: curl <pod-ip>:2112/healthz
```

---

## 11. 快速复习卡片

### 5 分钟快速回顾

```
┌──────────────────────────────────────────────────────────┐
│                   5 分钟快速回顾                           │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  eBPF 探针: kprobe tcp_sendmsg → Ring Buffer → Go 用户态 │
│                                                           │
│  核心数据流: 捕获 → 拓扑 → 检测 → 根因 → 自愈 → 通知    │
│                                                           │
│  3 层保护: 受保护 IP + 冷却期 + 自适应阈值                │
│                                                           │
│  异常分数 = 延迟因子 × 错误因子 + 调用量骤降 × 权重      │
│                                                           │
│  根因算法: 反向随机游走 (PageRank 变体, 50轮迭代)        │
│                                                           │
│  自愈闭环: TC 丢包 → K8s 重启 → 火焰图 → 飞书通知        │
│                                                           │
│  4 个 eBPF 程序: net_trace + tcp_conntrack + tc_drop +   │
│                  http_probe                               │
│                                                           │
│  零侵入: 不改代码, 不加 Sidecar, 内核级采集               │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

### 面试话术速记

```
"介绍一下这个项目"
  "一个基于 eBPF 的零侵入微服务可观测与自愈平台。
   在内核层捕获 TCP 通信，构建调用拓扑，用图算法定位根因，
   自动执行 TC 限流和 K8s Pod 重启，同时采集火焰图作为现场证据。"

"eBPF 为什么安全？"
  "有内核验证器检查所有程序——有界循环、边界检查、
   禁止直接访问内核函数。不会因为 eBPF 程序的 bug 搞崩系统。"

"怎么定位根因？"
  "反向随机游走算法。在反向图上执行 PageRank 变体，
   从异常节点向上游传播嫌疑分数，找到最可能的根因。
   加上故障集群分组和历史模式匹配。"

"和传统监控比优势在哪？"
  "零侵入。不需要改代码、不需要加 Sidecar、不需要重启服务。
   内核级采集对应用完全透明。"
```

### eBPF 概念速记

```
kprobe   → 内核函数入口/出口挂载
uprobe   → 用户态函数挂载
TC       → 网络数据包处理
CO-RE    → 一次编译，到处运行
BTF      → BPF Type Format（内核类型信息）
Ring Buf → 内核→用户态事件通道
BPF Map  → 内核→用户态共享数据
Verifier → 检查 eBPF 程序安全性
JIT      → 将 BPF 字节码编译为机器码
```
