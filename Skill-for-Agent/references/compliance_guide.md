---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '17a5f8ff-9165-4222-a96c-c39a3845301b'
  PropagateID: '17a5f8ff-9165-4222-a96c-c39a3845301b'
  ReservedCode1: '6daa5331-65c0-409f-84d8-855538207395'
  ReservedCode2: '6daa5331-65c0-409f-84d8-855538207395'
---

# 合规性设计规范

> 本文件定义"网络安全慧眼智能体"技能的合规边界，确保功能可安全上架。

## 合规原则

### 1. 纯防御性设计
- 所有功能仅用于**检测和防御**，不包含任何攻击性工具
- 不包含: 渗透测试工具、漏洞利用代码、暴力破解工具、嗅探器
- 包含: 进程行为分析、网络连接审计、配置检查、加固建议

### 2. 数据本地处理
- IP 归属地查询使用**离线数据库** (qqwry.dat / ipv6wry.db)，不联网查询
- 安全扫描结果默认不外发
- AI 分析为可选增强，需用户显式确认后才会外发脱敏数据

### 3. 数据脱敏
- 外发 AI 分析前，所有敏感信息（密钥、密码、令牌）自动脱敏
- 默认不发送内网 IP 和监听端口列表
- 遵循数据最小化原则，仅发送风险研判所需的最少信息

### 4. 无侵入性
- 所有检测使用**只读系统 API**（/proc 文件系统、psutil 读取）
- 不修改任何系统配置文件
- 不终止任何进程或阻断任何连接（仅在建议中提供操作命令）

### 5. 境外连接标注的中立性
- 基于 IP 归属地的公开地理信息标注"境外连接"
- 不含任何地缘政治定性或国家/地区歧视
- 用户可自行配置关注地区，默认仅标注非中国大陆的公网连接

## 功能边界

### ✅ 允许的功能
| 功能 | 说明 |
|------|------|
| 进程扫描 | 读取 /proc 文件系统和 psutil API 分析进程行为 |
| 网络连接审计 | 通过 ss 命令和 /proc/net/tcp 分析活跃连接 |
| 监听端口检查 | 列出所有 LISTEN 状态的端口和关联进程 |
| IP 归属地查询 | 使用离线数据库查询 IP 的地理信息 |
| CDN 识别 | 通过域名后缀匹配 CDN 厂商 |
| 路由追踪 | 调用系统 traceroute/mtr 进行路由追踪 |
| 防火墙状态检查 | 读取 ufw/firewalld/iptables 状态 |
| SSH 配置审计 | 读取 sshd_config 配置项 |
| 内核参数检查 | 通过 sysctl 读取内核安全参数 |
| 用户账户审计 | 读取 /etc/passwd 和 /etc/shadow 检查用户安全 |
| 失败登录检查 | 通过 lastb 命令检查最近失败登录 |
| MAC 状态检查 | 检查 SELinux/AppArmor 运行状态 |
| AI 风险分析 | 将脱敏后的风险数据发送给 AI 进行分析（需确认） |
| 加固建议 | 基于检查结果生成系统加固操作建议 |

### ❌ 禁止的功能
| 功能 | 原因 |
|------|------|
| 网络端口扫描 | 属于攻击性行为，可能违反法律 |
| 漏洞利用 | 属于攻击性行为 |
| 密码破解 | 属于攻击性行为 |
| 数据包嗅探/抓包 | 可能侵犯隐私或违反法律 |
| 进程注入 | 属于攻击性行为 |
| 远程控制 | 属于攻击性行为 |
| 发送安全事件到外部服务器 | 未经确认的数据外发 |
| 自动终止进程/阻断连接 | 可能影响正常业务，应由人工决策 |
| 修改系统配置 | 加固建议仅供人工参考执行 |
| 恶意软件样本库 | 包含恶意样本本身存在合规风险 |

## 数据库获取指引

### 纯真 IPv4 数据库 (qqwry.dat)
- 来源: github.com/metowolf/qqwry.dat
- 用途: IPv4 地址归属地离线查询
- 格式: 二进制，GB18030 编码
- 许可: 免费使用

### ZX IPv6 数据库 (ipv6wry.db)
- 来源: ip.zxinc.org
- 用途: IPv6 地址归属地离线查询
- 格式: 二进制，IPDB 格式
- 许可: 免费使用

### CDN 厂商域名库 (cdn.yml)
- 来源: github.com/SukkaLab/cdn
- 用途: CDN 厂商域名匹配
- 格式: YAML
- 许可: 开源

### 数据库放置位置（优先级从高到低）
1. 环境变量 `CYBER_EYE_DATA_DIR` 指定目录
2. 技能自带 `data/` 目录
3. `~/.local/share/cyber-eye/data/`
4. `/usr/share/cyber-eye/data/`

### 下载命令（用户自行执行）
```bash
# 创建数据目录
mkdir -p ~/.local/share/cyber-eye/data

# 下载纯真 IPv4 库
wget -O ~/.local/share/cyber-eye/data/qqwry.dat \
  https://github.com/metowolf/qqwry.dat/releases/latest/download/qqwry.dat

# 下载 IPv6 库（需 7z 解压）
wget -O /tmp/ip.7z https://ip.zxinc.org/ip.7z
7z x /tmp/ip.7z -o/tmp/
mv /tmp/ipv6wry.db ~/.local/share/cyber-eye/data/

# 下载 CDN 库
wget -O ~/.local/share/cyber-eye/data/cdn.yml \
  https://cdn.jsdelivr.net/gh/SukkaLab/cdn@main/cdn.yml
```

> AI生成