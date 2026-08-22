---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '50b54687-a620-42dd-ad4f-ccd7f4cd77cd'
  PropagateID: '50b54687-a620-42dd-ad4f-ccd7f4cd77cd'
  ReservedCode1: '6773d34a-8602-47c5-bc30-aeee86555d9b'
  ReservedCode2: '6773d34a-8602-47c5-bc30-aeee86555d9b'
---

# linmon — Linux 进程与网络连接安全监控工具

初学Linux的朋友，看着满屏的ps信息或者ss网络连接，蒙了，咋看？怎么了解哪些进程可能存在问题？有时候真心想呼唤火绒杀毒软件里面的一个组成部分：火绒剑，来帮你披荆斩棘，看清系统里面究竟在运行什么。
我用中国电信的星辰超级智能体（TeleAgent）制作了这个工具，希望能够帮到你。

轻量级 Linux 安全监控工具，提供命令行和 Web 面板两种使用方式。实时采集系统进程、网络连接信息，结合本地规则引擎和可选的 AI 分析，帮助快速发现可疑进程、异常网络外连等安全隐患。

## 功能特性

- **进程监控**：扫描全部进程，识别高危/可疑进程（可疑路径、异常用户、伪装进程名等），关联定时任务（cron / systemd timer / rc.local / init.d）、网络连接、祖先链和子进程
- **网络连接监控**：列出所有活跃网络连接，按协议/端口识别服务类型，查询 IP 归属地（纯真 IP 库），通过 TTL 指纹推断对端操作系统，评估连接风险等级
- **地理分布地图**：Web 面板内置 ECharts 世界地图，以**连线**展示本机（源点）到各远端 IP（目标点）的网络连接，连线**粗细按传输数据量（发送+接收）比例**缩放；远端仍以红/黄/绿散点标注，支持飞线动效、缩放拖拽和悬浮查看详情。地图头部提供**收起/打开**按钮，可临时隐藏地图以查看连接列表。点击任意**连线或远端节点**会弹出分析弹窗，汇总该位置下的全部进程与网络活动（进程名/PID/用户/命令行、远端地址、流量方向、数据量、风险研判与原因），并**自动追踪路由在地图上以带序号的紫色小弧线叠加显示数据逐跳建立的路径**（保留主连线）；点击**本机**节点则展示本机对外连接总览。本机源点坐标由 `web_config.json` 的 `home_coord`（[经度,纬度]）指定，缺省或探测不到出口公网 IP 时回退到中国中心
- **连接抓包分析**：在连接分析弹窗中可对单个连接发起**本地抓包**（`tcpdump`/`tshark`），展示收发字节数、包数、按本地端口关联的进程（PID/命令行），以及每个数据包的时间、方向、端口、TCP 标志、长度与载荷预览，帮助定位是哪个程序在持续外连、传输了什么数据。抓包仅在本机进行，**不对外发送任何数据**
- **路由跟踪**：逐跳显示路由路径及每跳的 IP 归属地，自动兼容 `traceroute`/`mtr`/`tracepath` 输出格式（含 `no reply` 跳与私网跳），可选 AI 分析路由安全性
- **AI 安全分析**：接入大语言模型，对高危进程、可疑连接生成结构化安全分析报告，给出风险评级和处置建议
- **Web 监控面板**：实时刷新的仪表盘界面，支持表头排序、自动刷新、一键复制 kill 命令、AI 分析弹窗
- **多发行版适配**：自动检测 Debian / RHEL / Arch / SUSE 系发行版，适配不同的包管理器和服务管理器

## 截图

Web 面板包含五个页面：

| 页面 | 说明 |
|------|------|
| 概览 | 系统信息卡片 + 进程类别分布 + 网络方向分布 |
| 进程监控 | 进程列表，表头可排序，点击展开详情，支持 AI 分析和一键 kill |
| 网络连接 | 连接列表 + 世界地图地理分布，表头可排序，支持 AI 分析 |
| 路由跟踪 | 输入目标 IP/域名，逐跳显示路由和归属地 |
| AI 分析 | 综合安全报告，可查看高危统计、配置和测试 AI 连接 |

## 快速开始

### 方式一：一键部署脚本

```bash
# 系统级安装到 /opt/linmon（需 sudo）
sudo ./deploy.sh

# 或用户级安装到 ~/linmon（无需 sudo）
./deploy.sh --user
```

安装完成后直接使用：

```bash
linmon boot              # 查看开机信息
linmon proc              # 进程监控
linmon net               # 网络连接监控
linmon diag              # 系统全面诊断
linmon trace 8.8.8.8     # 路由跟踪
linmon-web               # 启动 Web 监控面板
```

### 方式二：手动安装

```bash
# 1. 克隆仓库
git clone git@github.com:sakylian/linmon.git
cd linmon

# 2. 创建虚拟环境并安装依赖
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. 运行
python linmon.py proc          # 命令行模式
python webserver.py            # Web 模式，访问 http://localhost:8765
```

### 系统依赖

- Python >= 3.8
- `iproute2`（提供 `ss` 命令，网络连接扫描依赖）
- `traceroute`/`mtr`/`tracepath`（路由跟踪功能依赖，任一即可）
- `tcpdump` 或 `tshark`（连接抓包分析依赖，需 root 运行 Web 服务）

Debian / Ubuntu：
```bash
sudo apt install python3 python3-pip iproute2 traceroute net-tools
```

RHEL / CentOS / Rocky：
```bash
sudo dnf install python3 python3-pip iproute traceroute net-tools
```

## 命令行用法

```bash
linmon <子命令> [选项]
```

| 子命令 | 说明 | 常用选项 |
|--------|------|----------|
| `boot` | 显示开机信息 | — |
| `proc` | 进程监控 | `--all` 显示所有进程 / `--ai` AI分析 / `-o file.csv` 导出 |
| `net` | 网络连接监控 | `--all` 包含内部连接 / `--os` 探测对端OS / `--ai` AI分析 / `-o file.csv` 导出 |
| `diag` | 系统全面诊断 | `--ai` AI分析 / `-o report.txt` / `--csv data.csv` / `--json data.json` |
| `trace` | 路由跟踪 | `--hops 30` / `--timeout 5` / `--ai` |
| `web` | 启动Web服务 | `--host 0.0.0.0` / `--port 8765` / `--debug` |
| `ai-config` | AI配置管理 | `--show` / `--set key=val` / `--enable` / `--disable` / `--test` |

### 使用示例

```bash
# 只看高危进程
linmon proc

# 查看所有进程并导出 CSV
linmon proc --all -o processes.csv

# 网络监控 + 探测对端OS + AI分析
linmon net --os --ai

# 生成完整诊断报告（含AI分析）
linmon diag --ai -o report.txt --csv data.csv

# 路由跟踪到 Google DNS
linmon trace 8.8.8.8 --ai
```

## AI 分析配置

AI 分析为可选功能，默认关闭。配置后可对高危进程和可疑连接生成专业的安全分析报告。

```bash
# 设置 API 密钥
linmon ai-config --set app_key=你的AppKey

# 启用
linmon ai-config --enable

# 测试连接
linmon ai-config --test

# 查看配置
linmon ai-config --show
```

也可以直接编辑配置文件 `config/ai_config.json`，或通过 Web 面板的「AI 配置」按钮在线修改。

## 隐私与数据外发控制（商业化部署必读）

linmon 的 AI 分析需要把检测结果发往**第三方 LLM 端点**。为防止"检测误判时把系统关键信息泄露给第三方"，所有外发行为均做了最小化与显式确认：

- **默认不开机自动外发**：`auto_analyze` 类行为未自动触发，仅在你显式使用 `--ai` 或 Web 面板的「AI 分析」时才会外发。
- **发送前显式确认**：CLI 使用 `--ai` 会展示"将发送哪些字段 / 发往哪个端点"并需 `y/N` 确认（可用 `--yes` 跳过）；Web 面板在 AI 分析前弹出确认框。
- **命令行/密钥脱敏**：外发前自动遮蔽 `password`/`token`/`Authorization: Bearer`/`mysql -p`/连接串密码等敏感取值（仍建议生产环境配合离线模式）。
- **默认不发送内网拓扑**：本机内网 IP、监听端口列表默认**不**随连接/进程信息外发（`send_internal_ips` / `send_listening_ports` 默认 false）。
- **可一键离线**：设置 `allow_external_ai=false` 后，任何 AI 分析都不会向外部发送任何数据，仅返回本地结论。
- **Web 面板鉴权**：默认仅监听 `127.0.0.1`，且所有 `/api/*` 接口需 Bearer 令牌鉴权（令牌启动于终端打印并保存于 `config/web_config.json`，权限 0600）。

`config/ai_config.json` 新增/相关配置项：

```json
{
  "allow_external_ai": true,        // false 时完全离线，绝不外发
  "redact_sensitive": true,         // 外发前脱敏命令行/密钥
  "send_internal_ips": false,       // 是否随连接信息发送本机内网IP
  "send_listening_ports": false,    // 是否随进程信息发送监听端口
  "geo_risk_enabled": false,        // 启用"高风险地区外连"本地规则
  "high_risk_regions": []           // 高风险地区列表，如 ["美国","荷兰"]
}
```

> 说明（与早期文档的差异）：「高风险地区外连」本地判定默认**关闭**（避免误报），需显式开启并配置 `high_risk_regions`；「连接频率」分析由 Web 服务的后台采样线程持续采集后生效（CLI 一次性扫描无历史样本时为"无采样数据"，属正常）。

## 第三方数据授权（qqwry.dat / 纯真 IP 库）

IP 归属地查询依赖 **纯真 IP 库（`qqwry.dat`）**，该数据文件受纯真官方授权约束，**不得随本项目源码再分发**。因此：

- 仓库已通过 `.gitignore` 排除 `data/qqwry.dat`，并且该文件**不再纳入版本控制**（仅本地保留）。
- 部署脚本（`deploy.sh`）复制 `data/` 时会提示：`qqwry.dat` 如存在会被一并复制，但分发给他人前请确认已获得纯真 IP 库授权；若缺失则 IP 归属地功能不可用，不影响其它检测。
- 使用者需**自行获取授权**后将 `qqwry.dat` 放置于以下任一位置即可生效：`data/qqwry.dat`、`/etc/linmon/qqwry.dat`、`/usr/local/share/qqwry.dat`、`~/qqwry.dat`。
- 缺少该文件时，`geo_locator` 会优雅降级（归属地显示为"未知"），不会报错中断。

> 商业化发布前请务必确认：交付物中**不包含**未获授权的 `qqwry.dat`，否则可能产生数据授权合规风险。

## Web 面板

```bash
python webserver.py
# 或
linmon-web
```

启动后访问 `http://localhost:8765`。

功能：
- 概览页实时展示系统状态卡片
- 进程表和网络表支持点击表头排序、自动定时刷新
- 网络连接页内置世界地图：本机→远端连线（粗细按流量），远端按风险等级散点标注
- 每行进程支持 AI 分析和一键复制 kill 命令
- 路由跟踪可视化展示

## 项目结构

```
linmon/
├── linmon.py              # CLI 统一入口
├── webserver.py           # Flask Web 服务
├── deploy.sh              # 一键部署脚本
├── requirements.txt       # Python 依赖
├── .gitignore
├── config/
│   └── ai_config.json     # AI 配置（含密钥，已 gitignore）
├── data/
│   ├── qqwry.dat          # 纯真 IP 归属地数据库（第三方授权数据，需自行获取，不随仓库分发）
│   ├── echarts.min.js     # ECharts 图表库（地图）
│   └── world.json         # 世界地图 GeoJSON
├── templates/
│   └── index.html         # Web 面板前端（单文件）
└── modules/
    ├── proc_monitor.py    # 进程监控模块
    ├── net_monitor.py     # 网络连接监控模块
    ├── geo_locator.py     # IP 归属地查询 + 坐标映射
    ├── ai_analyzer.py     # AI 安全分析模块
    ├── distro_helper.py   # 发行版适配模块
    └── sys_diag.py        # 系统诊断报告生成
```

## 版本更新

### v1.0.0 — 首个正式版本

- 进程监控：高危进程识别、定时任务关联、网络连接、祖先链
- 网络连接监控：IP归属地查询、TTL指纹推断对端OS、风险评级
- Web 监控面板：ECharts 世界地图地理分布、表头排序、自动刷新
- 一键复制 kill 命令
- AI 安全分析：高危进程/可疑连接智能分析报告
- 路由跟踪：逐跳归属地显示
- 多发行版适配：Debian/RHEL/Arch/SUSE
- 一键部署脚本 deploy.sh + 命令安装脚本 install.sh
- CLI 命令包装：linmon / linmon-web 全局命令

## 技术栈

- **后端**：Python 3 / Flask / psutil
- **前端**：原生 HTML+JS+CSS（单文件） / ECharts（世界地图）
- **IP 归属地**：纯真 IP 数据库（qqwry.dat）
- **AI 分析**：兼容 OpenAI API 格式的大语言模型

## 支持的 Linux 发行版

- Debian / Ubuntu / LinuxMint / Kali / Raspbian
- RHEL / CentOS / Rocky / AlmaLinux / Fedora
- Arch / Manjaro
- openSUSE / SLES

## License

MIT

> AI生成