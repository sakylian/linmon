#!/usr/bin/env python3
"""
security_scan.py — 系统安全扫描器 (跨平台: Linux/macOS/Windows)

功能：
  1. 扫描所有进程的高危特征（恶意软件、反弹 Shell、挖矿、可疑路径等）
  2. 扫描所有网络连接的高危情况（高危端口、主动监听、境外连接等）
  3. 输出结构化 JSON 报告供 LLM 分析

合规设计：
  - 所有检测使用跨平台系统 API (psutil)，不发送任何数据到外部
  - 不包含任何攻击性/渗透测试功能，纯防御性扫描
  - 不含已知恶意软件样本库（仅基于行为特征检测）
  - 境外连接判断基于 IP 归属地的公开地理信息，不含任何地缘政治定性
"""

import os
import sys
import re
import json
import time
import socket
import struct
import hashlib
import subprocess
import platform

# 将同目录的 geo_locator 加入路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from geo_locator import (
    GeoLocator, is_private_ip, is_valid_public_ip, is_ipv6,
    classify_port, HIGH_RISK_PORTS, guess_remote_os
)

try:
    import psutil
except ImportError:
    print('错误: 需要 psutil 库，请运行: pip install psutil', file=sys.stderr)
    sys.exit(1)


# ──────────────────────── 平台检测 ────────────────────────

IS_WINDOWS = sys.platform == 'win32'
IS_MACOS = sys.platform == 'darwin'
IS_LINUX = sys.platform.startswith('linux')


# ──────────────────────── 威胁模式定义 ────────────────────────

# 反向 Shell 命令行特征（纯特征匹配，不含攻击代码）
REV_SHELL_PATTERNS = [
    '/dev/tcp/', 'bash -i ', 'nc -e ', 'ncat -e ', 'socat exec:',
    'pty.spawn', 'socket.socket(', 'sh -i', '/dev/udp/',
    # Windows 反弹 Shell 特征
    'powershell -nop -w hidden', 'powershell -enc ', 'iex(new-object',
    'net.webclient).downloadstring',
]

# 下载即执行特征
DOWNLOAD_CMDS = ['curl ', 'wget ', 'fetch ', 'powershell -c ', 'certutil ', 'bitsadmin ']
SHELL_INTERPS = ['bash', 'sh', 'python', 'python3', 'perl', 'ruby',
                 'powershell', 'pwsh', 'cmd']

# 挖矿特征
MINING_PATTERNS = [
    'stratum+tcp://', 'stratum+ssl://', 'xmrpool', 'nanopool',
    '--donate-level', 'cryptonight', 'ethash', 'mining.',
]

# 已知恶意软件进程名特征
MALWARE_NAME_HINTS = {
    'xmrig', 'cryptominer', 'minerd', 'kdevtmpfsi', 'kinsing',
    'cpuminer', 'ccminer', 'ethminer', 'tsm', 'pwnrig',
    'malware', 'trojan', 'backdoor', 'rootkit', 'botnet',
}

# 可疑路径（跨平台）
SUSPICIOUS_PATHS = [
    '/tmp/', '/dev/shm/', '/var/tmp/', '/dev/.', '/proc/',
    # Windows
    '\\temp\\', '\\tmp\\', '\\windows\\temp\\', '\\appdata\\local\\temp\\',
    'c:\\temp\\', 'c:\\tmp\\',
    # macOS
    '/private/tmp/', '/private/var/tmp/',
]

# 安全扫描工具（不应长期运行）
SCAN_TOOLS = {'nmap', 'masscan', 'hydra', 'john', 'hashcat', 'medusa',
              'nmap.exe', 'masscan.exe'}

# 网络工具（监听时可能是后门）
NET_TOOLS = {'nc', 'ncat', 'socat', 'netcat', 'nc.exe', 'ncat.exe'}

# 系统服务用户（exe 不可读是正常的）
SYSTEM_USERS = {
    # Linux
    'avahi', 'messagebus', 'polkitd', 'rtkit', 'colord', 'syslog',
    'systemd-resolve', 'systemd-timesync', 'systemd-network',
    'systemd-coredump', 'nobody', 'Debian-exim', 'postfix', 'mail',
    'news', 'uucp', 'www-data', 'nginx', 'apache', 'mysql', 'postgres',
    'redis', 'mongodb', 'kernoops', 'cups', 'lp', 'gnats', 'irc',
    'list', 'backup', 'man', 'proxy', 'saned', 'speech-dispatcher',
    'hplip', 'geoclue', 'nm-openvpn', 'fwupd',
    # Windows
    'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'WinRM',
    'IIS_IUSRS', 'MSSQL', 'SQLServer', 'WMI', 'UMFD-0', 'UMFD-1',
    # macOS
    '_windowserver', '_spotlight', '_sslh', '_postgres', '_mysql',
    '_redis', '_www', '_daemon', '_lp', '_uucp', '_nod', '_appleevents',
}

SAFE_NO_EXE_NAMES = {
    '(sd-pam)', 'fusermount3', 'fusermount', 'kthreadd',
    # Windows
    'System', 'Registry', 'smss.exe', 'csrss.exe', 'winlogon.exe',
    'Services.exe', 'lsass.exe', 'svchost.exe', 'Memory Compression',
    # macOS
    'kernel_task', 'launchd', 'windowserver',
}


# ──────────────────────── 进程扫描 ────────────────────────

def _sha256_file(path):
    """计算文件 SHA256"""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _detect_malware_signals(proc_info):
    """多维恶意特征研判"""
    name = (proc_info.get('name', '') or '').lower()
    cmdline = (proc_info.get('cmdline', '') or '').lower()
    exe = proc_info.get('exe', '') or ''
    reasons = []

    # 反向 Shell
    if any(p in cmdline for p in REV_SHELL_PATTERNS):
        reasons.append('高危: 命令行含反向Shell特征')

    # 下载即执行
    if any(d in cmdline for d in DOWNLOAD_CMDS) and \
            any(f'| {s}' in cmdline or f'|{s}' in cmdline or
                f'; {s}' in cmdline or f';{s}' in cmdline for s in SHELL_INTERPS):
        reasons.append('高危: 命令行含下载即执行(dropper)特征')

    # 挖矿
    if any(p in cmdline for p in MINING_PATTERNS):
        reasons.append('高危: 命令行含矿池/挖矿连接特征')

    # 恶意软件名称
    if name in MALWARE_NAME_HINTS:
        reasons.append('进程名匹配已知恶意软件特征')

    # 可疑路径
    if exe:
        exe_lower = exe.lower()
        if any(p.lower() in exe_lower for p in SUSPICIOUS_PATHS):
            reasons.append(f'可执行文件位于可疑路径: {exe}')

    # 已删除的二进制
    if exe and exe.endswith('(deleted)'):
        reasons.append('可执行文件已被删除但仍运行中（入侵残留）')

    return bool(reasons), reasons


def _is_kernel_thread_safe(proc_info):
    """安全的内核线程判断（跨平台）"""
    pid = proc_info.get('pid', 0)
    name = proc_info.get('name', '')
    if pid <= 0:
        return True
    # 内核线程通常没有 exe 和 cmdline
    if not proc_info.get('exe') and not proc_info.get('cmdline') and \
            proc_info.get('memory_percent', 0) == 0:
        return True
    # Windows/macOS 内核进程
    if name in SAFE_NO_EXE_NAMES:
        return True
    return False


def _detect_high_risk(proc_info):
    """检测高危进程"""
    name = proc_info.get('name', '').lower()
    exe = proc_info.get('exe', '') or ''
    username = proc_info.get('username', '')
    pid = proc_info.get('pid', 0)

    if _is_kernel_thread_safe(proc_info) or name in SAFE_NO_EXE_NAMES:
        return False, 'low', []

    risk_reasons = []

    # 恶意信号
    malware_hit, malware_reasons = _detect_malware_signals(proc_info)
    risk_reasons.extend(malware_reasons)

    # 网络工具监听
    if name in NET_TOOLS and proc_info.get('listening_ports'):
        risk_reasons.append(f'网络工具监听端口: {name} 监听 {proc_info["listening_ports"]}')

    # 扫描工具运行
    if name in SCAN_TOOLS:
        risk_reasons.append(f'安全扫描工具运行中: {name}')

    # exe 不可读（非系统用户）
    if not exe and pid > 1 and not _is_kernel_thread_safe(proc_info):
        if username and username not in SYSTEM_USERS:
            risk_reasons.append('进程可执行文件路径不可读（可能已隐藏或已删除）')

    # Shell 外连
    if name in ('bash', 'sh', 'zsh', 'python', 'python3', 'perl',
                'powershell', 'pwsh', 'cmd') and \
            proc_info.get('network_connections'):
        for c in proc_info['network_connections']:
            remote_ip = c.get('remote_ip', '')
            if c.get('state') == 'ESTABLISHED' and c.get('remote_port', 0) > 0 and \
                    is_valid_public_ip(remote_ip):
                risk_reasons.append(f'Shell/脚本进程持有外网连接: {remote_ip}:{c["remote_port"]}')
                break

    is_risky = len(risk_reasons) > 0
    risk_level = 'high' if any('高危' in r or '恶意' in r for r in risk_reasons) else \
                 'medium' if is_risky else 'low'

    return is_risky, risk_level, risk_reasons


def get_all_processes(max_procs=500):
    """获取所有进程的安全分析结果（跨平台）"""
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline',
                                      'username', 'create_time', 'memory_percent',
                                      'cpu_percent', 'status', 'uids']):
        try:
            info = proc.info
            pname = info.get('name', '') or ''
            pexe = info.get('exe', '') or ''
            pcmdline = ' '.join(info.get('cmdline') or [])
            ppid = info.get('ppid', 0)
            pid = info.get('pid', 0)

            # 关联网络连接
            net_conns = []
            try:
                for c in proc.net_connections(kind='inet'):
                    conn = {
                        'local_ip': c.laddr.ip if c.laddr else '',
                        'local_port': c.laddr.port if c.laddr else 0,
                        'remote_ip': c.raddr.ip if c.raddr else '',
                        'remote_port': c.raddr.port if c.raddr else 0,
                        'state': c.status,
                        'fd': c.fd,
                    }
                    net_conns.append(conn)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # 监听端口
            listening_ports = [c['local_port'] for c in net_conns
                               if c['state'] == 'LISTEN' and c['local_port']]

            proc_info = {
                'pid': pid,
                'ppid': ppid,
                'name': pname,
                'exe': pexe,
                'cmdline': pcmdline,
                'username': info.get('username', ''),
                'create_time': info.get('create_time', 0),
                'memory_percent': info.get('memory_percent', 0),
                'cpu_percent': info.get('cpu_percent', 0),
                'status': info.get('status', ''),
                'listening_ports': listening_ports,
                'network_connections': net_conns,
                'net_conn_count': len(net_conns),
            }

            is_risky, risk_level, risk_reasons = _detect_high_risk(proc_info)
            proc_info['is_risky'] = is_risky
            proc_info['risk_level'] = risk_level
            proc_info['risk_reasons'] = risk_reasons

            processes.append(proc_info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 排序：高危 > 中危 > 低危
    processes.sort(key=lambda p: {'high': 0, 'medium': 1, 'low': 2}.get(p['risk_level'], 3))

    return processes


def get_risky_processes(processes=None):
    """只返回有风险的进程"""
    if processes is None:
        processes = get_all_processes()
    return [p for p in processes if p['is_risky']]


# ──────────────────────── 网络连接扫描 ────────────────────────

def get_all_connections():
    """获取所有网络连接的安全分析（跨平台，使用 psutil）"""
    connections = []
    seen = set()

    try:
        all_conns = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, PermissionError):
        return []

    for c in all_conns:
        local_ip = c.laddr.ip if c.laddr else ''
        local_port = c.laddr.port if c.laddr else 0
        remote_ip = c.raddr.ip if c.raddr else ''
        remote_port = c.raddr.port if c.raddr else 0
        state = c.status or ''

        # 协议判断
        if c.family == socket.AF_INET6:
            proto = 'tcp6' if c.type == socket.SOCK_STREAM else 'udp6'
        else:
            proto = 'tcp' if c.type == socket.SOCK_STREAM else 'udp'

        # 获取进程信息
        process = ''
        pid = c.pid or 0
        if pid:
            try:
                process = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        direction = _determine_direction(local_port, remote_port, state)

        geo = None
        if remote_ip and is_valid_public_ip(remote_ip):
            geo = GeoLocator.lookup_ip(remote_ip)

        # 去重
        key = f"{remote_ip}:{remote_port}:{process}:{local_port}"
        if key in seen and state != 'LISTEN':
            continue
        seen.add(key)

        conn = {
            'proto': proto,
            'state': state,
            'local_ip': local_ip,
            'local_port': local_port,
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'process': process,
            'pid': pid,
            'direction': direction,
            'geo': geo,
        }
        conn = _assess_connection_risk(conn)
        connections.append(conn)

    return connections


def _determine_direction(local_port, remote_port, state):
    """判断连接方向"""
    if state == 'LISTEN':
        return 'listen'
    if remote_port == 0:
        return 'listen'
    # 本地端口小 → 通常是入站
    if local_port < 1024 and remote_port > 1024:
        return 'inbound'
    # 远程端口小 → 通常是出站
    if remote_port < 1024 and local_port > 1024:
        return 'outbound'
    # 默认出站
    return 'outbound'


def _assess_connection_risk(conn):
    """评估连接风险"""
    reasons = []
    remote_ip = conn.get('remote_ip', '')
    remote_port = conn.get('remote_port', 0)
    local_port = conn.get('local_port', 0)
    direction = conn.get('direction', 'unknown')
    process = conn.get('process', '')
    state = conn.get('state', '')

    # LISTEN 状态
    if direction == 'listen' or state == 'LISTEN':
        proto_name, risk = classify_port(local_port)
        if risk == 'high':
            reasons.append(f'高危监听端口: {local_port} ({proto_name})')
        if any(name in process.lower() for name in
               ('nc', 'ncat', 'socat', 'python', 'perl', 'bash', 'sh',
                'powershell', 'cmd')):
            reasons.append(f'疑似后门监听: {process} 监听 {local_port}')
        conn['risk_level'] = 'high' if reasons else \
                             'medium' if classify_port(local_port)[1] == 'medium' else 'low'
        conn['risk_reasons'] = reasons
        return conn

    proto_name, risk = classify_port(remote_port)

    # 高危端口
    if risk == 'high':
        reasons.append(f'高危端口连接: {remote_port} ({proto_name})')

    # 后门端口
    if remote_port in HIGH_RISK_PORTS or local_port in HIGH_RISK_PORTS:
        reasons.append(f'可疑后门端口: {remote_port}')

    # 境外连接（仅标注，不做定性）
    geo = conn.get('geo', {})
    geo_str = geo.get('geo_str', '') if geo else ''
    if geo_str and geo_str != '未知':
        is_domestic = any(kw in geo_str for kw in [
            '北京', '上海', '广州', '深圳', '杭州', '南京', '成都', '武汉',
            '西安', '重庆', '苏州', '天津', '青岛', '长沙', '郑州', '合肥',
            '济南', '南昌', '福州', '厦门', '昆明', '大连', '沈阳', '长春',
            '哈尔滨', '石家庄', '太原', '兰州', '贵阳', '南宁', '海口', '三亚',
            '拉萨', '银川', '西宁', '乌鲁木齐', '呼和浩特', '香港', '澳门',
            '台北', '高雄', '漳州', '泉州', '莆田', '宁德', '龙岩', '三明',
            '南平', '东莞', '佛山', '珠海', '中山', '惠州', '汕头', '湛江',
            '无锡', '南通', '徐州', '常州', '扬州', '温州', '宁波', '绍兴',
            '嘉兴', '金华', '台州', '烟台', '威海', '潍坊',
            '中国', '本机', '局域网',
        ])
        if not is_domestic and is_valid_public_ip(remote_ip):
            reasons.append(f'境外连接: {remote_ip} → {geo_str}')

    # SSH/RDP 入站
    if remote_port == 22 and direction == 'inbound':
        reasons.append('SSH入站连接(需确认合法性)')
    if remote_port == 3389 and direction == 'inbound':
        reasons.append('RDP入站连接(需确认合法性)')

    # 反弹 Shell
    if process and any(name in process.lower() for name in
                       ('bash', 'sh', 'python', 'perl', 'nc', 'socat',
                        'powershell', 'pwsh', 'cmd')):
        if direction == 'outbound' and is_valid_public_ip(remote_ip):
            reasons.append(f'疑似反弹Shell: {process} 外连到 {remote_ip}')

    # 非标准高端口
    if remote_port > 49151 and direction == 'outbound' and is_valid_public_ip(remote_ip):
        reasons.append(f'外连到非标准高端口: {remote_port}')

    # 确定风险等级
    conn['risk_level'] = 'high' if any('后门' in r or '反弹' in r or '高危' in r for r in reasons) else \
                         'medium' if reasons else 'low'
    conn['risk_reasons'] = reasons
    return conn


# ──────────────────────── 防火墙检查 ────────────────────────

def check_firewall():
    """检查防火墙状态（跨平台）"""
    if IS_WINDOWS:
        return _check_firewall_windows()
    elif IS_MACOS:
        return _check_firewall_macos()
    else:
        return _check_firewall_linux()


def _check_firewall_linux():
    """Linux 防火墙检查"""
    result = {'ufw': None, 'firewalld': None, 'iptables': None}

    # ufw
    try:
        r = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            result['ufw'] = 'active' if 'Status: active' in r.stdout else 'inactive'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # firewalld
    try:
        r = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            result['firewalld'] = r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # iptables
    try:
        r = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            lines = r.stdout.strip().split('\n')
            result['iptables'] = f'{len(lines)} rules'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result['iptables'] = None

    return result


def _check_firewall_macos():
    """macOS 防火墙检查 (Application Firewall / pf)"""
    result = {'app_firewall': None, 'pf': None}

    # Application Firewall
    try:
        r = subprocess.run(
            ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            result['app_firewall'] = 'active' if 'enabled' in r.stdout.lower() else 'inactive'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # pf (packet filter)
    try:
        r = subprocess.run(['pfctl', '-s', 'info'], capture_output=True, text=True, timeout=5)
        combined = (r.stdout or '') + (r.stderr or '')
        if 'Status: Enabled' in combined:
            result['pf'] = 'active'
        elif 'Status: Disabled' in combined:
            result['pf'] = 'inactive'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return result


def _check_firewall_windows():
    """Windows 防火墙检查 (netsh advfirewall)"""
    result = {'domain': None, 'private': None, 'public': None}

    creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        r = subprocess.run(
            ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
            capture_output=True, text=True, timeout=10,
            creationflags=creationflags,
        )
        if r.returncode == 0:
            current_profile = None
            for line in r.stdout.split('\n'):
                line = line.strip()
                low = line.lower()
                if 'profile configuration' in low or 'profile settings' in low:
                    # e.g., "Domain Profile Configuration:"
                    parts = line.split()
                    if parts:
                        current_profile = parts[0].lower()
                elif current_profile and ('OFF' in line.upper()):
                    result[current_profile] = 'inactive'
                elif current_profile and ('ON' in line.upper()):
                    result[current_profile] = 'active'
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return result


def check_listening_ports():
    """检查所有监听端口"""
    connections = get_all_connections()
    listening = [c for c in connections if c.get('direction') == 'listen' or c.get('state') == 'LISTEN']
    result = []
    for c in listening:
        proto_name, risk = classify_port(c['local_port'])
        result.append({
            'port': c['local_port'],
            'proto': c.get('proto', 'tcp'),
            'process': c.get('process', ''),
            'pid': c.get('pid', 0),
            'service': proto_name,
            'risk': risk,
            'bind': c.get('local_ip', ''),
        })
    result.sort(key=lambda x: ({'high': 0, 'medium': 1, 'low': 2}.get(x['risk'], 3), x['port']))
    return result


# ──────────────────────── 编译摘要 ────────────────────────

def generate_scan_summary(risky_procs=None, risky_conns=None, listening=None, fw=None):
    """生成扫描摘要供 LLM 分析"""
    if risky_procs is None:
        risky_procs = get_risky_processes()
    if risky_conns is None:
        all_conns = get_all_connections()
        risky_conns = [c for c in all_conns if c['risk_level'] != 'low']
    if listening is None:
        listening = check_listening_ports()
    if fw is None:
        fw = check_firewall()

    high_procs = [p for p in risky_procs if p['risk_level'] == 'high']
    medium_procs = [p for p in risky_procs if p['risk_level'] == 'medium']
    high_conns = [c for c in risky_conns if c['risk_level'] == 'high']
    medium_conns = [c for c in risky_conns if c['risk_level'] == 'medium']
    high_listening = [l for l in listening if l['risk'] == 'high']

    return {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'platform': platform.platform(),
        'summary': {
            'high_risk_processes': len(high_procs),
            'medium_risk_processes': len(medium_procs),
            'high_risk_connections': len(high_conns),
            'medium_risk_connections': len(medium_conns),
            'high_risk_listening_ports': len(high_listening),
            'firewall_status': fw,
        },
        'high_risk_processes': high_procs,
        'medium_risk_processes': medium_procs,
        'high_risk_connections': high_conns,
        'medium_risk_connections': medium_conns,
        'high_risk_listening_ports': high_listening,
        'all_listening_ports': listening,
    }


# ──────────────────────── CLI ────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description='系统安全扫描器 (跨平台)')
    parser.add_argument('--json', action='store_true', help='输出 JSON 格式')
    parser.add_argument('--processes', action='store_true', help='仅扫描进程')
    parser.add_argument('--connections', action='store_true', help='仅扫描网络连接')
    parser.add_argument('--listening', action='store_true', help='仅检查监听端口')
    parser.add_argument('--firewall', action='store_true', help='仅检查防火墙')
    args = parser.parse_args()

    if args.firewall:
        fw = check_firewall()
        if args.json:
            print(json.dumps(fw, ensure_ascii=False, indent=2))
        else:
            for k, v in fw.items():
                print(f'{k}: {v or "未检测到"}')
        return

    if args.listening:
        ports = check_listening_ports()
        if args.json:
            print(json.dumps(ports, ensure_ascii=False, indent=2))
        else:
            print(f'\n监听端口 ({len(ports)} 个):')
            print(f'{"端口":<8} {"协议":<6} {"服务":<16} {"风险":<8} {"进程":<20} {"绑定地址"}')
            print('-' * 80)
            for p in ports:
                print(f'{p["port"]:<8} {p["proto"]:<6} {p["service"]:<16} {p["risk"]:<8} {p["process"]:<20} {p["bind"]}')
        return

    if args.processes:
        procs = get_all_processes()
        risky = [p for p in procs if p['is_risky']]
        if args.json:
            print(json.dumps(risky, ensure_ascii=False, indent=2, default=str))
        else:
            print(f'\n进程扫描完成: 共 {len(procs)} 个进程, {len(risky)} 个有风险')
            for p in risky:
                print(f'\n[{p["risk_level"].upper()}] PID={p["pid"]} {p["name"]} (用户: {p["username"]})')
                if p['cmdline']:
                    print(f'  命令行: {p["cmdline"][:120]}')
                for r in p['risk_reasons']:
                    print(f'  ⚠ {r}')
        return

    if args.connections:
        conns = get_all_connections()
        risky = [c for c in conns if c['risk_level'] != 'low']
        if args.json:
            print(json.dumps(risky, ensure_ascii=False, indent=2, default=str))
        else:
            print(f'\n网络连接扫描完成: 共 {len(conns)} 条, {len(risky)} 条有风险')
            for c in risky:
                geo_str = c.get('geo', {}).get('geo_str', '') if c.get('geo') else ''
                print(f'\n[{c["risk_level"].upper()}] {c["proto"]} {c["state"]} '
                      f'{c["local_ip"]}:{c["local_port"]} → {c["remote_ip"]}:{c["remote_port"]}')
                if geo_str:
                    print(f'  归属地: {geo_str}')
                if c.get('process'):
                    print(f'  进程: {c["process"]} (PID={c.get("pid", 0)})')
                for r in c['risk_reasons']:
                    print(f'  ⚠ {r}')
        return

    # 默认：完整扫描
    summary = generate_scan_summary()
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    else:
        s = summary['summary']
        print(f'\n{"="*60}')
        print(f'系统安全扫描报告 — {summary["timestamp"]}')
        print(f'平台: {summary.get("platform", "unknown")}')
        print(f'{"="*60}')
        print(f'\n高危进程: {s["high_risk_processes"]}  中危进程: {s["medium_risk_processes"]}')
        print(f'高危连接: {s["high_risk_connections"]}  中危连接: {s["medium_risk_connections"]}')
        print(f'高危监听: {s["high_risk_listening_ports"]}')
        fw = s['firewall_status']
        fw_parts = [f'{k}={v}' for k, v in fw.items() if v]
        fw_str = '  '.join(fw_parts) if fw_parts else '未检测到防火墙'
        print(f'防火墙: {fw_str}')

        for p in summary['high_risk_processes']:
            print(f'\n[高危进程] PID={p["pid"]} {p["name"]} (用户: {p["username"]})')
            if p['cmdline']:
                print(f'  命令行: {p["cmdline"][:120]}')
            for r in p['risk_reasons']:
                print(f'  ⚠ {r}')

        for c in summary['high_risk_connections']:
            geo_str = c.get('geo', {}).get('geo_str', '') if c.get('geo') else ''
            print(f'\n[高危连接] {c["proto"]} {c["state"]} '
                  f'{c["remote_ip"]}:{c["remote_port"]} ({geo_str})')
            if c.get('process'):
                print(f'  进程: {c["process"]} (PID={c.get("pid", 0)})')
            for r in c['risk_reasons']:
                print(f'  ⚠ {r}')

        for l in summary['high_risk_listening_ports']:
            print(f'\n[高危监听] 端口 {l["port"]} ({l["service"]})  进程: {l["process"]}')

        if not summary['high_risk_processes'] and not summary['high_risk_connections'] \
           and not summary['high_risk_listening_ports']:
            print('\n✓ 未发现高危项')


if __name__ == '__main__':
    main()
