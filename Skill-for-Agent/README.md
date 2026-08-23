# Skill-for-Agent — 智能体技能源文件

本目录是**给智能体（Agent）使用的技能源文件**，包含技能定义、可调用脚本与参考知识，
适用于需要在多种操作系统上执行**纯防御性**系统安全巡检的智能体。

> 这不是一个独立可运行的程序，而是一套"技能包（Skill）"：智能体加载 `SKILL.md`
> 后即可理解何时、如何调用 `scripts/` 下的脚本完成安全扫描、路由追踪、加固建议等任务。

## 技能一览

| 字段 | 内容 |
|------|------|
| 技能名（英文） | `cyber-security-eye` |
| 技能名（中文） | 网络安全慧眼智能体 |
| 定位 | 系统安全巡检与威胁分析（纯防御性） |
| 适用平台 | **Linux / macOS / Windows**（跨平台，基于 `psutil`） |
| 源定义 | `SKILL.md`（含 frontmatter 元数据，兼容主流 Agent 技能加载器） |

## 目录结构

```
Skill-for-Agent/
├── SKILL.md                      # 技能定义（智能体入口，含 frontmatter 元数据）
├── README.md                     # 本文件：技能源文件说明
├── scripts/                      # 智能体可执行的检测脚本
│   ├── security_scan.py          # 进程/网络/监听端口/防火墙安全扫描
│   ├── geo_locator.py            # IP 归属地离线查询（IPv4/IPv6，支持管道模式）
│   ├── route_trace.py            # 路由追踪 + 每跳中文位置标注
│   └── hardening_advisor.py      # 系统安全配置检查 + 加固建议
└── references/                   # 智能体参考知识
    ├── threat_patterns.md        # 威胁行为特征、检测模式、数据脱敏规范
    └── compliance_guide.md       # 功能边界、数据库获取指引、合规原则
```

## 如何被智能体使用

- 智能体读取 `SKILL.md` 的 `description` / `description_cn` 判断何时触发本技能
  （如用户说"检查系统安全""路由追踪""境外连接""系统加固""网络安全"等）。
- 触发后按 `SKILL.md` 的工作流程调用 `scripts/` 下的脚本，解析其 JSON 输出。
- 所有脚本支持 `--json` 输出，便于智能体解析；`geo_locator.py` 另支持管道模式（类 nali）。

## 多系统支持

| 平台 | 进程/网络扫描 | 路由追踪 | 防火墙检查 | 加固建议 |
|------|-------------|---------|-----------|---------|
| Linux | psutil API | traceroute/mtr/tracepath | ufw/firewalld/iptables | SSH/内核参数/SELinux/AppArmor |
| macOS | psutil API | traceroute/mtr & `traceroute6` | Application Firewall/pf | Gatekeeper/SIP/FileVault/SSH |
| Windows | psutil API | `tracert`（内置） | Windows Defender Firewall | UAC/Defender/RDP/账户锁定 |

## 合规要点

- 纯防御性，不含任何攻击功能；检测仅使用只读系统 API，不修改系统配置。
- IP 归属地查询使用**离线数据库**，不联网；AI 外发数据前必须脱敏并获得用户确认。
- 境外连接标注基于公开地理信息，**不做地缘政治定性**。

详见 `SKILL.md` 与 `references/`。
