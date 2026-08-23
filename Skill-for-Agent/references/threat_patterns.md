---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '9ce83919-ed85-4180-8542-98975a9877b6'
  PropagateID: '9ce83919-ed85-4180-8542-98975a9877b6'
  ReservedCode1: '1793e65d-9948-487a-bb07-74a8f96386bb'
  ReservedCode2: '1793e65d-9948-487a-bb07-74a8f96386bb'
---

# 威胁检测模式参考

> 本文件供 LLM 在分析安全扫描结果时参考，包含各类威胁的行为特征和判断依据。
> 所有检测均基于行为特征匹配，不包含任何攻击代码或渗透测试工具。

## 目录
1. [进程威胁](#进程威胁)
2. [网络威胁](#网络威胁)
3. [风险等级定义](#风险等级定义)
4. [数据脱敏规范](#数据脱敏规范)

## 进程威胁

### 反向 Shell (Reverse Shell)
**特征**: 攻击者通过被攻陷主机主动外连到控制端，获得交互式 Shell。
**检测模式**:
- 命令行含 `/dev/tcp/` 或 `/dev/udp/`（Bash 内置网络重定向）
- 命令行含 `bash -i`（交互式 Bash 外连）
- 命令行含 `nc -e` 或 `ncat -e`（Netcat 执行模式）
- 命令行含 `socat exec:`（Socat 执行模式）
- 命令行含 `pty.spawn`（Python 伪终端）
- 命令行含 `socket.socket(`（Python 原始 Socket）
**关联条件**: Shell/脚本进程 (bash/sh/python/perl) 持有 ESTABLISHED 状态的公网 IP 连接。

### 下载即执行 (Dropper)
**特征**: 从远程下载脚本并通过管道直接执行，常见于恶意软件安装。
**检测模式**: 命令行同时包含下载命令 (`curl`/`wget`/`fetch`) 和管道解释器 (`| bash`/`| sh`/`| python`)。

### 挖矿程序 (Cryptominer)
**特征**: 利用系统资源进行加密货币挖矿。
**检测模式**:
- 命令行含 `stratum+tcp://` 或 `stratum+ssl://`（矿池协议）
- 命令行含已知矿池域名 (`xmrpool`, `nanopool`, `mining.`)
- 命令行含 `--donate-level`（XMRig 参数）
- 命令行含 `cryptonight`, `ethash`（挖矿算法）
- 进程名匹配已知矿工 (`xmrig`, `minerd`, `kdevtmpfsi`, `kinsing`, `cpuminer`)

### 恶意软件残留
**特征**: 可执行文件已被删除但进程仍在运行（入侵后清理痕迹）。
**检测模式**: `os.readlink('/proc/<pid>/exe')` 返回值以 `(deleted)` 结尾。

### 可疑路径
**特征**: 恶意软件常从临时目录运行以规避检测。
**检测路径**: `/tmp/`, `/dev/shm/`, `/var/tmp/`, `/dev/.`, `/proc/`

### 后门监听
**特征**: 网络工具 (nc/ncat/socat) 在监听端口，可能是攻击者植入的后门。
**检测模式**: 进程名为 nc/ncat/socat/python/perl/bash 且持有 LISTEN 状态端口。

### 安全工具滥用
**特征**: 系统上运行网络扫描或密码破解工具，可能是攻击者在横向移动。
**检测进程名**: nmap, masscan, hydra, john, hashcat, medusa

## 网络威胁

### 高危端口
以下端口因常被恶意软件使用而被标记为高危:

| 端口 | 服务 | 风险 | 说明 |
|------|------|------|------|
| 4444 | Metasploit | high | Metasploit 默认反向 Shell 端口 |
| 1337 | Backdoor | high | 常见后门端口 |
| 5555 | ADB/Backdoor | high | Android Debug Bridge / 后门 |
| 8444 | FRP | high | FRP 内网穿透常用端口 |
| 29999 | FRP Dashboard | high | FRP 管理面板 |
| 10080 | FRP HTTP | high | FRP HTTP 代理 |
| 10443 | FRP HTTPS | high | FRP HTTPS 代理 |
| 21 | FTP | high | 明文传输 |
| 22 | SSH | high | 暴力破解目标 |
| 23 | Telnet | high | 明文传输 |
| 445 | SMB | high | 勒索软件常用攻击面 |
| 1433 | MSSQL | high | 数据库暴力破解 |
| 3306 | MySQL | high | 数据库暴力破解 |
| 3389 | RDP | high | 远程桌面暴力破解 |
| 5900 | VNC | high | 远程桌面暴力破解 |
| 6379 | Redis | high | 未授权访问 |
| 27017 | MongoDB | high | 未授权访问 |
| 2375 | Docker | high | Docker API 未授权 |
| 5984 | CouchDB | high | 未授权访问 |
| 11211 | Memcached | high | UDP 放大攻击 |

### 境外连接
**说明**: 系统连接到境外 IP 不一定代表威胁，但需要关注:
- 系统是否有业务需求连接到该地区
- 连接频率是否异常（高频持续连接 vs 偶发 DNS 查询）
- 关联进程是否合理

**标注方式**: 基于 IP 归属地离线数据库 (纯真 qqwry.dat / ZX ipv6wry.db) 查询，
将非中国大陆的公网连接标注为"境外连接"，不做地缘政治定性。

### 非标准端口外连
**特征**: 外连到 49152 以上的动态端口范围，可能是 P2P 或 C2 通信。
**判断**: 需结合进程身份和连接频率综合分析。

## 风险等级定义

| 等级 | 含义 | 示例 |
|------|------|------|
| critical | 需立即处置 | 发现恶意进程运行中、已知后门端口活跃 |
| high | 高度可疑 | 反向 Shell 特征、矿池连接、高危端口 |
| medium | 需进一步确认 | 非标准端口外连、境外连接、SSH 入站 |
| low | 正常/可接受 | HTTPS、DNS、已知服务端口 |

## 数据脱敏规范

当需要调用 AI 分析风险点时，外发数据必须经过脱敏处理:

### 必须脱敏的内容
1. **私钥块**: `-----BEGIN ... PRIVATE KEY-----` → `[REDACTED-KEY]`
2. **信用卡号**: 16 位数字 → `[REDACTED]`
3. **URI 连接串密码**: `scheme://user:pass@host` → `scheme://user:[REDACTED]@host`
4. **Bearer 令牌**: `Bearer xxx` → `Bearer [REDACTED]`
5. **Authorization 头**: → `Authorization: [REDACTED]`
6. **MySQL 密码**: `-pPASSWORD` → `[REDACTED]`
7. **通用 key=value**: `password=xxx` / `api_key: xxx` → `xxx=[REDACTED]`

### 默认不外发的内容
- 本机内网 IP 地址
- 监听端口列表
- 进程的完整环境变量
- 系统用户密码哈希

### AI 分析的数据最小化原则
- 仅发送与风险判断相关的进程信息 (名称/PID/命令行脱敏后/风险原因)
- 仅发送与风险判断相关的连接信息 (远端IP/端口/归属地/进程名/风险原因)
- 限制单次分析的数据量 (最多 10 个高危进程 + 20 条可疑连接)
- AI 调用前向用户展示数据摘要并确认

> AI生成