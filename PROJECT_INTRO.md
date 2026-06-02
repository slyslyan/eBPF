# eBPF-AutoHeal — 无侵入可观测与自愈平台

## 项目是什么

基于 eBPF 的零侵入微服务可观测与自愈平台。在内核层捕获所有 TCP 通信，自动构建调用拓扑，用图算法定位故障根因，触发内核级自愈操作并保留故障现场。完整实现 SRE 闭环：**发现 → 定位 → 自愈 → 现场保全 → 通知**。

## 技术栈

| 层 | 技术 |
|----|------|
| 内核 | eBPF、kprobe/kretprobe、TC、uprobe、CO-RE、BPF Map、Ring Buffer |
| eBPF C 程序 | `net_trace.c`、`tcp_conntrack.c`、`tc_drop.c`、`http_probe.c` |
| 用户态 | Go 1.24、cilium/ebpf、bpf2go |
| 算法 | EMA 指数移动平均、滑动窗口 P95、反向随机游走（PageRank）、Jaccard 相似度、Top-K 聚类 |
| 监控 | Prometheus client_golang（8 个业务指标 + 3 个自监控指标） |
| K8s | client-go（Pod 查找/删除）、DaemonSet 部署 |
| 通知 | 飞书 / 钉钉 Webhook |
| 容器 | Docker、Minikube |

## 核心功能

- **零侵入 TCP 采集**：kprobe 挂载 `tcp_sendmsg`，自动提取源/目标 IP、端口、延迟、进程名，无需修改应用代码
- **连接生命周期跟踪**：kprobe `tcp_connect` + `tcp_close` 测量真实连接持续时间（RTT）
- **服务身份解析**：读取 `/proc/pid/cgroup` 解析 K8s Pod 名 / Docker 容器名，30 秒 TTL 缓存
- **自适应阈值**：每条边维护滑动窗口 P95 + EMA 基线，避免固定阈值误报
- **多维度异常评分**：延迟比率 + 错误率 + 调用量骤降三因子综合打分
- **反向随机游走根因分析**：在反向图上执行 PageRank 变体，定位级联故障根因
- **故障集群分组**：分数相近的嫌疑节点归为一组，提示共享基础设施故障
- **历史模式匹配**：Jaccard 相似度对比历史故障记录，推荐处理方案
- **内核级自愈**：eBPF TC 100% 丢包限流（微秒级），回退到 tc 命令
- **K8s Pod 隔离**：client-go 查找嫌疑 IP 对应 Pod 并删除触发重建
- **HTTP/gRPC 协议解析**：uprobe 挂载 Go 运行时函数，获取方法/路径/状态码
- **故障现场保全**：自动采集 CPU 火焰图、内存火焰图、Goroutine dump、线程 dump、tcpdump 抓包
- **飞书通知**：根因分析摘要推送到 IM 群
- **探针自监控**：`/healthz` 健康检查 + 事件/错误计数器 + 运行状态指标

## 核心数据流

```
eBPF kprobe → Ring Buffer → Go 用户态解析
  → ServiceGraph 更新拓扑（EMA + P95）
  → 定时根因分析（异常评分 + 反向随机游走）
  → 自愈执行（TC 限流 / K8s 重启 / 火焰图 / 抓包）
  → 飞书告警
```

## 项目结构

```
bpf/                        # eBPF C 源码（★ 核心）
├── net_trace.c             # TCP 延迟探针（kprobe/tcp_sendmsg）
├── tcp_conntrack.c         # 连接跟踪（kprobe/tcp_connect + tcp_close）
├── tc_drop.c               # TC 入口丢包程序
├── http_probe.c            # HTTP/gRPC uprobe
└── vmlinux.h               # 内核类型定义（CO-RE）

cmd/tracer/                 # Go 用户态程序
├── main.go                 # 入口 + eBPF 加载 + 事件循环
├── analysis.go             # ★ 根因分析引擎（核心算法）
├── graph.go                # 服务拓扑图（节点/边/EMA/P95）
├── mitigation.go           # 自愈操作（TC/K8s/火焰图/通知）
├── resolver.go             # cgroup 服务身份解析
├── http_probe.go           # HTTP/gRPC 事件消费
├── tc_drop.go              # eBPF TC 程序管理
├── config.go               # 配置系统
├── metrics.go              # Prometheus 指标
└── metrics_helper.go       # 标签基数保护

deploy/                     # K8s DaemonSet 部署
```
