---
name: cyber-security-eye
description: >-
  Network security inspection skill: scan system processes and network connections
  for high-risk threats (malware, reverse shells, mining, backdoor ports, suspicious
  outbound connections, overseas connections), trace route paths with Chinese
  geo-annotation for every hop (IPv4+IPv6, offline IP database, inspired by nali),
  call AI to analyze detected risks, and generate system hardening recommendations.
  Use when the user asks to "check system security", "scan for threats", "trace
  route to an IP", "check network connections", "security audit", "hardening",
  "网络安全", "安全扫描", "进程分析", "网络连接检查", "路由追踪", "系统加固",
  "境外连接", "高危端口", "反弹Shell", "安全巡检", or similar security-defensive tasks.
name_cn: 网络安全慧眼智能体
description_cn: >-
  系统安全巡检与威胁分析：扫描进程和网络连接的高危行为（恶意软件、反弹Shell、
  挖矿、后门端口、境外连接等），路由追踪并中文标注每跳位置（支持IPv4/IPv6离线查询），
  AI分析风险点，生成系统加固建议。
create_source: super-agent-skill-creator
---

# 网络安全慧眼智能体

纯防御性的系统安全巡检技能，支持 **Linux / macOS / Windows** 三大平台。
所有检测使用只读跨平台系统 API（psutil），
不修改任何系统配置、不发送数据到外部（AI 分析需用户显式确认）。

## 平台兼容性

| 平台 | 进程/网络扫描 | 路由追踪 | 防火墙检查 | 加固建议 |
|------|-------------|---------|-----------|---------|
| Linux | psutil API | traceroute/mtr/tracepath | ufw/firewalld/iptables | SSH/内核参数/SELinux/AppArmor |
| macOS | psutil API | traceroute/mtr & `traceroute6` | Application Firewall/pf | Gatekeeper/SIP/FileVault/SSH |
| Windows | psutil API | `tracert`（内置） | Windows Defender Firewall | UAC/Defender/RDP/账户锁定 |

## 前置条件

- Python 3.8+，已安装 `psutil`（`pip install psutil`）
- **路由追踪**：
  - Linux: `traceroute`（`sudo apt install traceroute` 或 `sudo yum install traceroute`）
  - macOS: `traceroute`（系统内置）或 `brew install mtr`
  - Windows: `tracert`（系统内置，无需安装）
- IP 归属地查询需离线数据库，详见 [合规性指南](references/compliance_guide.md) 的"数据库获取指引"章节
  - 可通过环境变量 `CYBER_EYE_DATA_DIR` 指定数据库目录

## 脚本路径

所有脚本位于 `scripts/` 目录，通过 `python3 <脚本路径>` 执行：

| 脚本 | 功能 |
|------|------|
| `scripts/security_scan.py` | 进程安全扫描 + 网络连接审计 + 监听端口检查 |
| `scripts/geo_locator.py` | IP 归属地离线查询（IPv4/IPv6），支持管道模式（类似 nali） |
| `scripts/route_trace.py` | 路由追踪 + 每跳中文位置标注 |
| `scripts/hardening_advisor.py` | 系统安全配置检查 + 加固建议生成 |

## 工作流程

### 1. 安全扫描（进程 + 网络 + 端口）

运行完整扫描并获取 JSON 结果：

```bash
python3 scripts/security_scan.py --json
```

也可分别扫描：

```bash
# 仅进程
python3 scripts/security_scan.py --processes --json

# 仅网络连接
python3 scripts/security_scan.py --connections --json

# 仅监听端口
python3 scripts/security_scan.py --listening --json

# 仅防火墙状态
python3 scripts/security_scan.py --firewall --json
```

扫描输出结构化 JSON，包含以下字段：
- `summary`: 高危/中危的进程数、连接数、监听端口数、防火墙状态
- `high_risk_processes`: 高危进程列表（PID/名称/命令行/风险原因）
- `medium_risk_processes`: 中危进程列表
- `high_risk_connections`: 高危连接列表（远端IP/端口/归属地/进程/风险原因）
- `medium_risk_connections`: 中危连接列表
- `high_risk_listening_ports`: 高危监听端口
- `all_listening_ports`: 所有监听端口

### 2. AI 分析风险点

当扫描发现高危/中危项目时，执行 AI 分析：

1. 读取扫描结果 JSON
2. 提取风险项目的关键信息（进程名/PID/风险原因/远端IP/归属地/端口）
3. **必须脱敏**：移除命令行中的密码、密钥、令牌（参考 [威胁模式参考](references/threat_patterns.md) 的"数据脱敏规范"章节）
4. 将脱敏后的数据整理为分析 prompt，调用 LLM 进行分析
5. AI 分析维度：
   - 该进程/连接是否可能为恶意行为
   - 攻击者可能的入侵路径
   - 是否存在持久化机制
   - 建议的处置方案

**合规要求**：
- 外发前必须告知用户将发送哪些数据，获得确认
- 命令行中的敏感信息必须脱敏（密码、密钥、令牌）
- 默认不发送内网 IP 和监听端口列表
- 单次分析限制：最多 10 个高危进程 + 20 条可疑连接

### 3. 路由追踪（高危 IP 的连接路径分析）

对扫描发现的高危 IP，追踪网络路由路径并标注每跳的中文位置：

```bash
python3 scripts/route_trace.py <目标IP或域名> --json
python3 scripts/route_trace.py <目标IP或域名> --hops 30 --timeout 5
```

输出每一跳的：
- 跳序号、IP 地址、主机名、RTT 延迟
- **中文归属地**（使用离线 IP 数据库查询，同时支持 IPv4 和 IPv6）
- CDN 厂商（如果匹配到 CDN 域名）
- 跨境标记（如果路径跨越国家边界）

管道模式（类似 nali，在文本的 IP 后附加归属地）：

```bash
echo "连接来自 8.8.8.8 和 2001:4860:4860::8888" | python3 scripts/geo_locator.py -p
# 输出: 连接来自 8.8.8.8 [美国 加利福尼亚州...] 和 2001:4860:4860::8888 [美国...]
```

直接查询模式：

```bash
python3 scripts/geo_locator.py 8.8.8.8 1.1.1.1 2001:4860:4860::8888
```

### 4. 系统加固建议

生成系统安全配置检查报告和加固建议：

```bash
python3 scripts/hardening_advisor.py --json
python3 scripts/hardening_advisor.py --check-only  # 仅检查不生成建议
```

检查项根据平台自动适配：
- **Linux**: 防火墙状态、SSH 配置、用户账户安全、内核安全参数、SELinux/AppArmor、失败登录、自动更新
- **macOS**: 应用层防火墙、Gatekeeper、SIP、FileVault 磁盘加密、SSH 配置、自动更新
- **Windows**: Windows Defender 防火墙、UAC、Windows Defender 防病毒、RDP 配置、管理员账户、账户锁定策略

可结合安全扫描结果生成针对性建议：

```python
# 在 Python 中调用
import json, subprocess
scan_result = json.loads(subprocess.run(
    ['python3', 'scripts/security_scan.py', '--json'],
    capture_output=True, text=True
).stdout)
# 将 scan_result 传给 hardening_advisor.generate_hardening_advice(scan_summary=scan_result)
```

### 5. 综合安全报告

整合所有结果，向用户输出完整安全报告：

1. 运行 `security_scan.py --json` 获取扫描结果
2. 对高危项运行 `route_trace.py` 追踪路径
3. 运行 `hardening_advisor.py --json` 获取加固建议
4. 如果用户要求 AI 分析，脱敏后调用 LLM 分析高危项
5. 汇总为可读报告，包含：
   - 风险概览（高危/中危数量统计）
   - 高危进程详情（进程名/PID/命令行/风险原因/处置建议）
   - 高危连接详情（远端IP/端口/归属地/进程/路由路径/风险原因）
   - 高危监听端口（端口/服务/进程/处置建议）
   - 系统加固建议（按优先级排序）
   - AI 分析结论（如果调用了 AI）

## 参考资源

- [威胁模式参考](references/threat_patterns.md): 各类威胁的行为特征、检测模式、风险等级定义、数据脱敏规范
- [合规性指南](references/compliance_guide.md): 功能边界定义、数据库获取指引、合规原则

## 合规要点

- 本技能为**纯防御性工具**，不包含任何攻击性功能
- 所有检测使用**只读跨平台系统 API (psutil)**，不修改系统配置
- 不依赖 `/proc` 文件系统或平台专属命令（`ss` 等），确保跨平台兼容
- AI 分析外发数据前**必须脱敏**并获得用户确认
- IP 归属地查询使用**离线数据库**，不联网查询
- 境外连接标注基于公开地理信息，**不做地缘政治定性**
- 加固建议仅供人工参考，不由技能自动执行
