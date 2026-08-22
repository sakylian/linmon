#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
proc_monitor.py — 进程详细监控模块
功能：采集进程启动时间/启动用户/关联进程/定时启动检测/网络连接/使用端口
"""

import os
import time
import socket
import struct
import subprocess
import logging
from datetime import datetime
from collections import defaultdict

try:
    import psutil
except ImportError:
    psutil = None

from .distro_helper import get_distro

logger = logging.getLogger(__name__)

# Linux 常见进程知识库
PROCESS_DB = {
    # 系统核心
    'systemd': ('系统和服务管理器(init)', 'system', 5),
    'systemd-journald': ('日志服务', 'system', 3),
    'systemd-udevd': ('设备管理', 'system', 5),
    'systemd-logind': ('登录管理', 'system', 5),
    'systemd-resolved': ('DNS解析', 'system', 5),
    'systemd-networkd': ('网络管理', 'system', 5),
    'systemd-timesyncd': ('时间同步', 'system', 5),
    'init': ('传统init进程(PID 1)', 'system', 5),
    'kthreadd': ('内核线程管理', 'kernel', 1),
    'kworker': ('内核工作线程', 'kernel', 1),
    'ksoftirqd': ('软中断处理', 'kernel', 1),
    'rcu_sched': ('RCU调度', 'kernel', 1),
    'migration': ('CPU迁移', 'kernel', 1),
    'watchdog': ('看门狗', 'kernel', 1),
    # 网络服务
    'sshd': ('SSH安全Shell服务', 'network', 5),
    'nginx': ('Nginx Web服务器', 'network', 10),
    'apache2': ('Apache Web服务器', 'network', 10),
    'httpd': ('Apache Web服务器', 'network', 10),
    'dockerd': ('Docker引擎', 'service', 10),
    'containerd': ('容器运行时', 'service', 10),
    'docker-proxy': ('Docker代理', 'service', 10),
    'snmpd': ('SNMP监控', 'network', 10),
    'rsyslogd': ('系统日志', 'system', 5),
    'cron': ('定时任务服务', 'system', 5),
    'crond': ('定时任务服务', 'system', 5),
    'atd': ('一次性定时任务', 'system', 5),
    'dbus-daemon': ('系统总线', 'system', 5),
    'NetworkManager': ('网络管理', 'system', 10),
    'networkd-dispatcher': ('网络事件分发', 'system', 5),
    'polkitd': ('权限管理', 'system', 5),
    # 数据库
    'mysqld': ('MySQL数据库', 'database', 10),
    'mariadbd': ('MariaDB数据库', 'database', 10),
    'postgres': ('PostgreSQL数据库', 'database', 10),
    'redis-server': ('Redis缓存', 'database', 10),
    'mongod': ('MongoDB数据库', 'database', 10),
    # 安全相关
    'agetty': ('终端登录', 'system', 3),
    'login': ('用户登录', 'system', 3),
    'sudo': ('权限提升', 'security', 3),
    'su': ('用户切换', 'security', 3),
    'fail2ban-server': ('入侵防护', 'security', 5),
    'clamd': ('ClamAV杀毒', 'security', 10),
    'firewalld': ('防火墙', 'security', 5),
    'nft': ('nftables防火墙', 'security', 5),
    'iptables': ('iptables防火墙', 'security', 5),
    'auditd': ('审计服务', 'security', 5),
    # 可疑/后门相关
    'nc': ('NetCat(可能被用于后门)', 'suspicious', 1),
    'ncat': ('Ncat(可能被用于后门)', 'suspicious', 1),
    'socat': ('Socat(可能被用于后门)', 'suspicious', 1),
    'cryptominer': ('挖矿程序(高危)', 'malware', 1),
    'xmrig': ('XMRig挖矿(高危)', 'malware', 1),
    'kdevtmpfsi': ('伪装挖矿(高危)', 'malware', 1),
    'kinsing': ('Kinsing挖矿(高危)', 'malware', 1),
    'minerd': ('CPUMiner挖矿(高危)', 'malware', 1),
    # 开发/运维工具
    'python': ('Python解释器', 'runtime', 5),
    'python3': ('Python3解释器', 'runtime', 5),
    'node': ('Node.js运行时', 'runtime', 5),
    'java': ('Java运行时', 'runtime', 10),
    'gunicorn': ('Python WSGI', 'runtime', 5),
    'uwsgi': ('Python WSGI', 'runtime', 5),
    'php-fpm': ('PHP-FPM', 'runtime', 5),
    'php': ('PHP解释器', 'runtime', 5),
    'ruby': ('Ruby解释器', 'runtime', 5),
    'go': ('Go运行时', 'runtime', 5),
    # 系统工具
    'bash': ('Bash Shell', 'shell', 1),
    'sh': ('Shell', 'shell', 1),
    'zsh': ('Zsh Shell', 'shell', 1),
    'top': ('系统监控', 'tool', 1),
    'htop': ('系统监控', 'tool', 1),
    'vim': ('文本编辑器', 'tool', 1),
    'nano': ('文本编辑器', 'tool', 1),
    'git': ('版本控制', 'tool', 1),
    'curl': ('HTTP工具', 'tool', 1),
    'wget': ('下载工具', 'tool', 1),
    'ss': ('网络连接查看', 'tool', 1),
    'netstat': ('网络连接查看', 'tool', 1),
    'lsof': ('文件/端口查看', 'tool', 1),
    'tcpdump': ('抓包工具', 'tool', 1),
    'nmap': ('端口扫描(需关注)', 'security', 1),
    'masscan': ('高速端口扫描(需关注)', 'security', 1),
    'hydra': ('密码爆破(高危)', 'security', 1),
    'john': ('密码破解(高危)', 'security', 1),
}


def get_process_description(proc_name):
    """从知识库获取进程说明"""
    base = proc_name.lower().strip()
    # 去除路径前缀
    if '/' in base:
        base = base.rsplit('/', 1)[-1]
    if base in PROCESS_DB:
        desc, category, threshold = PROCESS_DB[base]
        return desc, category, threshold
    # 模糊匹配
    for key, (desc, cat, thresh) in PROCESS_DB.items():
        if base.startswith(key):
            return desc, cat, thresh
    return '未知进程', 'unknown', 10


def _read_proc_status(pid):
    """读取 /proc/[pid]/status"""
    info = {}
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if ':' in line:
                    key, val = line.split(':', 1)
                    info[key.strip()] = val.strip()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
    return info


def _read_proc_stat(pid):
    """读取 /proc/[pid]/stat 的关键字段"""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            data = f.read()
        # 处理 comm 中可能包含空格和括号的情况
        start = data.find('(')
        end = data.rfind(')')
        if start < 0 or end < 0:
            return None
        comm = data[start+1:end]
        rest = data[end+1:].strip().split()
        return {
            'comm': comm,
            'state': rest[0] if len(rest) > 0 else '?',
            'ppid': int(rest[1]) if len(rest) > 1 else 0,
            'pgrp': int(rest[2]) if len(rest) > 2 else 0,
            'session': int(rest[3]) if len(rest) > 3 else 0,
            'tty_nr': int(rest[4]) if len(rest) > 4 else 0,
            'start_time': int(rest[19]) if len(rest) > 19 else 0,  # clock ticks
            'vsize': int(rest[20]) if len(rest) > 20 else 0,  # bytes
            'rss': int(rest[21]) if len(rest) > 21 else 0,  # pages
        }
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
        return None


def _read_proc_cmdline(pid):
    """读取 /proc/[pid]/cmdline"""
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            data = f.read()
        return data.replace('\x00', ' ').strip() or ''
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return ''


def _read_proc_io(pid):
    """读取 /proc/[pid]/io (需要读取权限)"""
    info = {}
    try:
        with open(f'/proc/{pid}/io', 'r') as f:
            for line in f:
                if ':' in line:
                    key, val = line.split(':', 1)
                    info[key.strip()] = int(val.strip())
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
    return info


def _uid_to_username(uid):
    """UID → 用户名"""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return f'uid:{uid}'


def _parse_proc_net_tcp(path='/proc/net/tcp'):
    """解析 /proc/net/tcp 获取网络连接表"""
    connections = []
    try:
        with open(path, 'r') as f:
            lines = f.readlines()
        if len(lines) < 2:
            return connections
        # 格式: sl local_address rem_address st tx_queue rx_queue ...
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local_ip_hex, local_port_hex = parts[1].split(':')
                rem_ip_hex, rem_port_hex = parts[2].split(':')
                state = int(parts[3], 16)
                # tx_queue:rx_queue 在 parts[4]
                tx_rx = parts[4].split(':')
                tx_queue = int(tx_rx[0], 16)
                rx_queue = int(tx_rx[1], 16)

                local_ip = socket.inet_ntoa(struct.pack('<I', int(local_ip_hex, 16)))
                local_port = int(local_port_hex, 16)
                rem_ip = socket.inet_ntoa(struct.pack('<I', int(rem_ip_hex, 16)))
                rem_port = int(rem_port_hex, 16)

                # inode 用于关联 PID
                inode = int(parts[9]) if len(parts) > 9 else 0

                connections.append({
                    'local_ip': local_ip, 'local_port': local_port,
                    'remote_ip': rem_ip, 'remote_port': rem_port,
                    'state': state, 'tx_queue': tx_queue, 'rx_queue': rx_queue,
                    'inode': inode,
                    'protocol': 'tcp',
                })
            except (ValueError, struct.error, IndexError):
                continue
    except (FileNotFoundError, PermissionError):
        pass
    return connections


def _parse_proc_net_tcp6(path='/proc/net/tcp6'):
    """解析 /proc/net/tcp6"""
    connections = []
    try:
        with open(path, 'r') as f:
            lines = f.readlines()
        if len(lines) < 2:
            return connections
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local_ip_hex, local_port_hex = parts[1].split(':')
                rem_ip_hex, rem_port_hex = parts[2].split(':')
                state = int(parts[3], 16)
                inode = int(parts[9]) if len(parts) > 9 else 0
                local_port = int(local_port_hex, 16)
                rem_port = int(rem_port_hex, 16)

                # IPv6 地址: 4个32位小端
                ip_hex = local_ip_hex
                if ip_hex == '00000000000000000000000000000000':
                    local_ip = '::'
                else:
                    b = bytes.fromhex(ip_hex)
                    local_ip = socket.inet_ntop(socket.AF_INET6, b[::-1])

                ip_hex = rem_ip_hex
                if ip_hex == '00000000000000000000000000000000':
                    rem_ip = '::'
                else:
                    b = bytes.fromhex(ip_hex)
                    rem_ip = socket.inet_ntop(socket.AF_INET6, b[::-1])

                connections.append({
                    'local_ip': local_ip, 'local_port': local_port,
                    'remote_ip': rem_ip, 'remote_port': rem_port,
                    'state': state, 'inode': inode,
                    'protocol': 'tcp6',
                })
            except (ValueError, struct.error, IndexError):
                continue
    except (FileNotFoundError, PermissionError):
        pass
    return connections


# TCP 状态码映射
TCP_STATES = {
    0x01: 'ESTABLISHED', 0x02: 'SYN_SENT', 0x03: 'SYN_RECV',
    0x04: 'FIN_WAIT1', 0x05: 'FIN_WAIT2', 0x06: 'TIME_WAIT',
    0x07: 'CLOSED', 0x08: 'CLOSE_WAIT', 0x09: 'LAST_ACK',
    0x0A: 'LISTEN', 0x0B: 'CLOSING',
}


def _get_pid_socket_inodes(pid):
    """获取进程持有的 socket inode 列表"""
    inodes = set()
    fd_dir = f'/proc/{pid}/fd'
    try:
        for fd_name in os.listdir(fd_dir):
            try:
                link = os.readlink(os.path.join(fd_dir, fd_name))
                if link.startswith('socket:['):
                    inode = int(link[8:-1])
                    inodes.add(inode)
            except (OSError, ValueError):
                continue
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
    return inodes


def _get_process_network_connections(pid):
    """获取指定进程的网络连接"""
    pid_inodes = _get_pid_socket_inodes(pid)
    if not pid_inodes:
        return [], set()

    all_conns = _parse_proc_net_tcp() + _parse_proc_net_tcp6()
    proc_conns = [c for c in all_conns if c['inode'] in pid_inodes]
    ports = set()
    for c in proc_conns:
        ports.add(c['local_port'])
        if c['remote_port'] > 0:
            ports.add(c['remote_port'])
    return proc_conns, ports


def _build_process_tree(processes_dict):
    """构建父子进程树关联"""
    # processes_dict: {pid: {'ppid': ..., 'name': ...}}
    children_map = defaultdict(list)
    for pid, info in processes_dict.items():
        children_map[info['ppid']].append(pid)

    def get_ancestors(pid, depth=10):
        """获取祖先进程链"""
        chain = []
        current = pid
        for _ in range(depth):
            if current not in processes_dict:
                break
            ppid = processes_dict[current]['ppid']
            if ppid == 0 or ppid == current:
                break
            if ppid in processes_dict:
                chain.append({
                    'pid': ppid,
                    'name': processes_dict[ppid].get('name', ''),
                })
                current = ppid
            else:
                break
        return chain

    def get_children(pid, depth=10):
        """获取子进程列表"""
        result = []
        queue = [(pid, 0)]
        while queue:
            curr, d = queue.pop(0)
            if d >= depth:
                continue
            for child_pid in children_map.get(curr, []):
                result.append({
                    'pid': child_pid,
                    'name': processes_dict.get(child_pid, {}).get('name', ''),
                })
                queue.append((child_pid, d + 1))
        return result

    return get_ancestors, get_children


def _detect_scheduled_tasks(proc_name, proc_cmdline, distro):
    """检测进程是否有定时启动配置"""
    sched_info = {
        'is_cron': False,
        'is_systemd_timer': False,
        'is_rc_local': False,
        'is_initd': False,
        'cron_entries': [],
        'systemd_timer_entries': [],
        'details': ''
    }

    proc_lower = proc_name.lower()
    cmd_lower = (proc_cmdline or '').lower()

    # 1. 检查 crontab
    cron_dirs = distro.get_cron_dirs()
    for cron_path in cron_dirs:
        try:
            if os.path.isfile(cron_path):
                with open(cron_path, 'r') as f:
                    content = f.read()
                if proc_lower in content.lower() or (cmd_lower and cmd_lower in content.lower()):
                    sched_info['is_cron'] = True
                    sched_info['cron_entries'].append(cron_path)
            elif os.path.isdir(cron_path):
                for entry in os.listdir(cron_path):
                    full_path = os.path.join(cron_path, entry)
                    if os.path.isfile(full_path):
                        try:
                            with open(full_path, 'r') as f:
                                content = f.read()
                            if proc_lower in content.lower() or (cmd_lower and cmd_lower in content.lower()):
                                sched_info['is_cron'] = True
                                sched_info['cron_entries'].append(full_path)
                        except (PermissionError, UnicodeDecodeError):
                            pass
        except (PermissionError, FileNotFoundError, UnicodeDecodeError):
            pass

    # 检查用户 crontab
    user_cron_dirs = ['/var/spool/cron/crontabs', '/var/spool/cron']
    for d in user_cron_dirs:
        if os.path.isdir(d):
            try:
                for entry in os.listdir(d):
                    full_path = os.path.join(d, entry)
                    if os.path.isfile(full_path):
                        try:
                            with open(full_path, 'r') as f:
                                content = f.read()
                            if proc_lower in content.lower() or (cmd_lower and cmd_lower in content.lower()):
                                sched_info['is_cron'] = True
                                sched_info['cron_entries'].append(f'{full_path} (用户:{entry})')
                        except (PermissionError, UnicodeDecodeError):
                            pass
            except (PermissionError, FileNotFoundError):
                pass

    # 2. 检查 systemd timers
    timers = distro.get_systemd_timers()
    for timer in timers:
        timer_unit = timer.get('unit', '') or ''
        timer_trigger = timer.get('activates', '') or ''
        if proc_lower in timer_unit.lower() or proc_lower in timer_trigger.lower():
            sched_info['is_systemd_timer'] = True
            sched_info['systemd_timer_entries'].append(
                f"{timer_unit} (触发: {timer_trigger}, 下次: {timer.get('next_elapse', '未知')})"
            )

    # 3. 检查 rc.local
    rc_local = distro.get_rc_local()
    if rc_local and (proc_lower in rc_local.lower() or (cmd_lower and cmd_lower in rc_local.lower())):
        sched_info['is_rc_local'] = True

    # 4. 检查 init.d
    initd_scripts = distro.get_initd_scripts()
    for script in initd_scripts:
        if proc_lower in script.lower():
            sched_info['is_initd'] = True
            break
    # 也检查init.d脚本内容
    for script_name in initd_scripts:
        script_path = f'/etc/init.d/{script_name}'
        try:
            with open(script_path, 'r') as f:
                content = f.read()
            if proc_lower in content.lower() or (cmd_lower and cmd_lower in content.lower()):
                sched_info['is_initd'] = True
                break
        except (PermissionError, UnicodeDecodeError):
            pass

    # 汇总
    parts = []
    if sched_info['is_cron']:
        parts.append(f"cron定时({', '.join(sched_info['cron_entries'][:3])})")
    if sched_info['is_systemd_timer']:
        parts.append(f"systemd定时({len(sched_info['systemd_timer_entries'])}个)")
    if sched_info['is_rc_local']:
        parts.append("/etc/rc.local自启")
    if sched_info['is_initd']:
        parts.append("/etc/init.d自启")
    sched_info['details'] = '; '.join(parts) if parts else '无定时/自启配置'

    return sched_info


def _is_kernel_thread(proc_info):
    """判断是否为内核线程"""
    # 内核线程特征: ppid=2 (kthreadd), 无exe路径, 无cmdline
    ppid = proc_info.get('ppid', 0)
    exe = proc_info.get('exe', '')
    cmdline = proc_info.get('cmdline', '')
    name = proc_info.get('name', '')
    # kthreadd 的子进程或名字以 kworker/kthread/irq/migration/cpuhp/rcu/watchdog 开头
    if ppid == 2:
        return True
    kernel_prefixes = ('kworker', 'kthread', 'irq/', 'migration/', 'cpuhp/',
                       'idle_inject', 'rcu_', 'rcu/', 'oom_reaper', 'watchdog',
                       'ksoftirqd', 'psimon', 'jbd2/', 'jfsI', 'jfsC', 'jfsS',
                       'ecryptfs', 'scsi_', 'card', 'spi', 'cros_ec', 'hwrng',
                       'pool_workqueue')
    if name.startswith(kernel_prefixes):
        return True
    # 无exe且无cmdline的进程（可能是内核线程或特权进程无法读取）
    if not exe and not cmdline and ppid <= 2:
        return True
    return False


def _exe_is_deleted(pid):
    """通过 /proc/<pid>/exe 符号链接判断是否已被删除（典型入侵残留）。

    注意：非特权用户读取其它用户的 /proc/<pid>/exe 会触发 PermissionError，
    此时无法确认是否删除，保守返回 False，由调用方结合扫描器权限判断。
    """
    try:
        target = os.readlink(f'/proc/{pid}/exe')
        return target.endswith(' (deleted)')
    except (OSError, ValueError):
        return False


# ---------- 多维恶意特征研判（降低漏报） ----------
# 说明：从“纯进程名匹配”升级为 名称 + 路径 + 命令行 + 文件哈希 综合研判。
# 哈希校验仅在其它信号命中时才触发，避免对全部进程逐一计算哈希带来的性能开销。

_MALWARE_NAME_HINTS = ('xmrig', 'cryptominer', 'minerd', 'kdevtmpfsi', 'kinsing')
_SUSPICIOUS_PATHS = ('/tmp/', '/dev/shm/', '/var/tmp/', '/dev/.', '/proc/')
# 反向Shell特征（避免过于宽泛的匹配导致误报，保留高置信度特征）
_REV_SHELL_PATTERNS = ('/dev/tcp/', 'bash -i ', 'nc -e ', 'ncat -e',
                       'exec 5<>/dev/tcp', 'pty.spawn', 'socket.socket(')
_DOWNLOAD_EXEC = ('curl', 'wget', 'fetch')
_SHELL_INTERP = ('bash', 'sh', 'python', 'python3', 'perl', 'ruby')
# 矿池/挖矿连接特征（保留高置信度特征，避免 -o 等通用参数误报）
_MINING_PATTERNS = ('stratum+tcp://', 'stratum+ssl://', 'xmrpool', 'nanopool',
                    'minergate', 'minexmr', 'supportxmr', '--donate-level')

# 已知恶意样本 SHA256 集合（可在此追加，或放置于 modules/malware_hashes.txt，每行: <hash> [描述]）
KNOWN_MALWARE_HASHES = {
    # 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': '示例占位',
}
_MALWARE_HASHES_CACHE = None


def _load_malware_hashes():
    """加载可选的恶意样本哈希库（modules/malware_hashes.txt），带缓存。"""
    global _MALWARE_HASHES_CACHE
    if _MALWARE_HASHES_CACHE is not None:
        return _MALWARE_HASHES_CACHE
    hashes = dict(KNOWN_MALWARE_HASHES)
    path = os.path.join(os.path.dirname(__file__), 'malware_hashes.txt')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                h = parts[0].lower()
                hashes[h] = parts[1] if len(parts) > 1 else ''
    except FileNotFoundError:
        pass
    _MALWARE_HASHES_CACHE = hashes
    return hashes


def _sha256_file(path, chunk=65536):
    import hashlib
    m = hashlib.sha256()
    with open(path, 'rb') as f:
        for blk in iter(lambda: f.read(chunk), b''):
            m.update(blk)
    return m.hexdigest()


def _detect_malware_signals(proc_info):
    """多维恶意特征研判，返回 (is_malware, reasons)。

    研判维度：
      - 进程名匹配已知恶意软件字典 (category=='malware' 或名称命中 _MALWARE_NAME_HINTS)
      - 可执行文件位于可疑路径 (临时目录/隐藏目录)
      - 命令行含反向Shell、下载即执行(dropper)、矿池连接等特征
      - 文件 SHA256 命中已知恶意样本库（仅在前述任一信号命中时计算，控制开销）
    """
    name = (proc_info.get('name', '') or '').lower()
    cmdline = (proc_info.get('cmdline', '') or '').lower()
    exe = proc_info.get('exe', '') or ''
    reasons = []

    name_hit = name in _MALWARE_NAME_HINTS or proc_info.get('category') == 'malware'
    path_hit = bool(exe) and any(p in exe for p in _SUSPICIOUS_PATHS)
    rev_hit = any(p in cmdline for p in _REV_SHELL_PATTERNS)

    if rev_hit:
        reasons.append('高危: 命令行含反向Shell特征')
    # 下载即执行：存在下载命令且通过管道交给解释器
    if any(d in cmdline for d in _DOWNLOAD_EXEC) and \
            any(f'| {s}' in cmdline for s in _SHELL_INTERP):
        reasons.append('高危: 命令行含下载即执行(dropper)特征')
    if any(p in cmdline for p in _MINING_PATTERNS):
        reasons.append('高危: 命令行含矿池/挖矿连接特征')
    if name_hit:
        reasons.append('进程名匹配已知恶意软件特征')
    if path_hit:
        reasons.append(f'可执行文件位于可疑路径: {exe}')

    # 多维命中时再做哈希校验（开销较大，仅在疑似时触发）
    if (name_hit or path_hit or rev_hit) and exe and os.path.isfile(exe):
        try:
            h = _sha256_file(exe)
            known = _load_malware_hashes()
            if h in known:
                reasons.append(f'高危: 可执行文件哈希命中已知恶意样本库: {known[h]}')
            elif known:
                reasons.append(f'可执行文件SHA256: {h}')
        except OSError:
            pass

    return bool(reasons), reasons


def _detect_high_risk(proc_info):
    """检测高危进程"""
    name = proc_info.get('name', '').lower()
    cmdline = (proc_info.get('cmdline', '') or '').lower()
    desc, category, _ = get_process_description(proc_info.get('name', ''))

    # 内核线程直接跳过
    if _is_kernel_thread(proc_info):
        return False, 'low', []

    risk_reasons = []

    # 多维恶意特征研判（名称 + 路径 + 命令行 + 哈希）
    malware_hit, malware_reasons = _detect_malware_signals(proc_info)
    risk_reasons.extend(malware_reasons)

    # 可疑网络工具
    if name in ('nc', 'ncat', 'socat') and proc_info.get('listening_ports'):
        risk_reasons.append(f'网络工具监听端口: {name} 监听 {proc_info["listening_ports"]}')
    if name in ('nmap', 'masscan'):
        risk_reasons.append(f'网络扫描工具运行中: {name}')
    if name in ('hydra', 'john', 'hashcat'):
        risk_reasons.append(f'密码破解工具运行中: {name}')

    # 可疑路径
    exe_path = proc_info.get('exe', '')
    if exe_path and ('/tmp/' in exe_path or '/dev/shm/' in exe_path):
        risk_reasons.append(f'从临时目录运行: {exe_path}')
    # exe 路径本身即标记为已删除（psutil 读到的 (deleted) 残留）
    if exe_path and exe_path.endswith(' (deleted)'):
        risk_reasons.append('可执行文件已被删除但仍运行中（典型入侵残留）')

    # 隐藏或无路径 (排除内核线程和已知系统服务用户)
    if not exe_path and proc_info.get('pid', 0) > 1:
        # 再次排除内核线程
        if not _is_kernel_thread(proc_info):
            # 一些系统服务进程可能因权限不足无法读取exe
            # 已知系统服务用户（非root但exe不可读是正常的）
            system_service_users = {
                'avahi', 'messagebus', 'polkitd', 'rtkit', 'colord',
                'syslog', 'systemd-resolve', 'systemd-timesync',
                'systemd-network', 'systemd-coredump', 'nobody',
                'Debian-exim', 'postfix', 'mail', 'news', 'uucp',
                'www-data', 'nginx', 'apache', 'mysql', 'postgres',
                'redis', 'mongodb', 'kernoops', 'cups', 'lp',
                'gnats', 'irc', 'list', 'backup', 'man', 'proxy',
                'saned', 'speech-dispatcher', 'hplip', 'geoclue',
                'nm-openvpn', ' Debian-+', 'fwupd', 'geoclue',
            }
            username = proc_info.get('username', '')
            name = proc_info.get('name', '')
            # 已知的 exe 不可读但安全的进程名
            safe_no_exe_names = {'(sd-pam)', 'fusermount3', 'fusermount'}
            if username in system_service_users or name in safe_no_exe_names:
                pass  # 系统服务用户，exe 不可读是正常的，不标记
            else:
                pid = proc_info.get('pid', 0)
                if _exe_is_deleted(pid):
                    # 高置信：二进制确实已被删除却仍在运行（与扫描器权限无关）
                    risk_reasons.append('可执行文件已被删除但仍运行中（典型入侵残留）')
                elif username and username != 'root':
                    # 非 root 进程：其 exe 在非特权下本应可读，不可读即可疑
                    risk_reasons.append('进程可执行文件路径不可读（可能已隐藏）')
                elif os.geteuid() == 0:
                    # root 进程：仅当扫描器本身也是 root 时才可疑；
                    # 否则多为权限不足导致的误报，不应标记
                    risk_reasons.append('root进程可执行文件路径不可读（可能已删除或隐藏）')

    # 反弹shell特征
    if name in ('bash', 'sh', 'zsh', 'python', 'python3') and proc_info.get('network_connections'):
        conns = proc_info['network_connections']
        from .geo_locator import is_valid_public_ip
        for c in conns:
            remote_ip = c.get('remote_ip', '')
            if c.get('state') == 0x01 and c.get('remote_port', 0) > 0 and is_valid_public_ip(remote_ip):
                risk_reasons.append(f'Shell/脚本进程持有外网连接: {remote_ip}:{c["remote_port"]}')
                break

    is_risky = len(risk_reasons) > 0
    risk_level = 'high' if category == 'malware' or any('高危' in r or '木马' in r or '恶意' in r for r in risk_reasons) else \
                 'medium' if is_risky else 'low'

    return is_risky, risk_level, risk_reasons


def get_all_processes(boot_time=None, scan_schedules=True, scan_network=True):
    """
    获取所有进程的详细信息
    返回 list[dict]，每个dict包含完整进程信息
    """
    if psutil is None:
        raise ImportError('psutil is required: pip install psutil')

    if boot_time is None:
        boot_time = psutil.boot_time()

    distro = get_distro()
    now = time.time()

    # 第一遍：收集所有进程基本信息
    raw_procs = {}
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline',
                                      'create_time', 'username', 'memory_info',
                                      'cpu_percent', 'status', 'uids']):
        try:
            info = proc.info
            pid = info['pid']
            raw_procs[pid] = {
                'pid': pid,
                'ppid': info['ppid'],
                'name': info['name'] or '',
                'exe': info['exe'] or '',
                'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else '',
                'create_time': info['create_time'] or 0,
                'username': info['username'] or 'unknown',
                'memory_rss': info['memory_info'].rss if info['memory_info'] else 0,
                'cpu_percent': info['cpu_percent'] or 0,
                'status': info['status'] or 'unknown',
                'uid': info['uids'].real if info['uids'] else 0,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # 构建进程树函数
    get_ancestors, get_children = _build_process_tree(raw_procs)

    # 第二遍：补充详细信息
    processes = []
    for pid, info in raw_procs.items():
        # 启动时间
        create_time = info['create_time']
        if create_time and boot_time:
            boot_delay = create_time - boot_time
        else:
            boot_delay = 0
        start_time_str = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M:%S') if create_time else '未知'

        # 进程说明
        desc, category, threshold = get_process_description(info['name'])

        # 关联进程
        ancestors = get_ancestors(pid)
        children = get_children(pid)

        # 定时启动检测
        if scan_schedules:
            sched = _detect_scheduled_tasks(info['name'], info['cmdline'], distro)
        else:
            sched = {'details': '未扫描', 'is_cron': False, 'is_systemd_timer': False,
                     'is_rc_local': False, 'is_initd': False, 'cron_entries': [], 'systemd_timer_entries': []}

        # 网络连接
        proc_conns = []
        used_ports = set()
        if scan_network:
            proc_conns, used_ports = _get_process_network_connections(pid)

        # 网络连接摘要
        conn_summary = []
        listening_ports = set()
        for c in proc_conns:
            state_name = TCP_STATES.get(c['state'], 'UNKNOWN')
            if c['state'] == 0x0A:  # LISTEN
                listening_ports.add(c['local_port'])
            elif c['state'] == 0x01:  # ESTABLISHED
                conn_summary.append({
                    'local': f"{c['local_ip']}:{c['local_port']}",
                    'remote': f"{c['remote_ip']}:{c['remote_port']}",
                    'state': state_name,
                    'protocol': c['protocol'],
                })

        # 格式化网络连接
        net_ports_str = ', '.join(sorted([str(p) for p in used_ports])) if used_ports else '无'
        net_conns_str = ''
        if conn_summary:
            net_conns_str = '; '.join([f"→{c['remote']}({c['state']})" for c in conn_summary[:5]])
            if len(conn_summary) > 5:
                net_conns_str += f' ...共{len(conn_summary)}条'
        elif listening_ports:
            net_conns_str = f"监听端口: {', '.join(str(p) for p in sorted(listening_ports))}"
        else:
            net_conns_str = '无活跃连接'

        proc_detail = {
            'pid': pid,
            'name': info['name'],
            'ppid': info['ppid'],
            'parent_name': raw_procs.get(info['ppid'], {}).get('name', ''),
            'exe': info['exe'],
            'cmdline': info['cmdline'],
            'username': info['username'],
            'uid': info['uid'],
            'status': info['status'],
            'description': desc,
            'category': category,
            'start_time': start_time_str,
            'start_timestamp': create_time,
            'boot_delay': boot_delay,
            'boot_delay_str': f'{boot_delay:.1f}秒' if boot_delay < 60 else f'{boot_delay/60:.1f}分钟' if boot_delay < 3600 else f'{boot_delay/3600:.1f}小时',
            'uptime': now - create_time if create_time else 0,
            'uptime_str': '',
            'memory_rss': info['memory_rss'],
            'memory_rss_str': _format_bytes(info['memory_rss']),
            'cpu_percent': round(info['cpu_percent'], 1),
            # 关联进程
            'ancestors': ancestors,
            'children': children,
            'ancestors_str': ' → '.join([f"{a['name']}({a['pid']})" for a in ancestors]) if ancestors else '无',
            'children_str': ', '.join([f"{c['name']}({c['pid']})" for c in children[:5]]) + (f' ...共{len(children)}个' if len(children) > 5 else '') if children else '无',
            # 定时任务
            'scheduled': sched,
            'is_cron': sched['is_cron'],
            'is_systemd_timer': sched['is_systemd_timer'],
            'is_rc_local': sched['is_rc_local'],
            'is_initd': sched['is_initd'],
            'schedule_str': sched['details'],
            # 网络
            'network_connections': proc_conns,
            'used_ports': sorted(used_ports),
            'listening_ports': sorted(listening_ports),
            'net_ports_str': net_ports_str,
            'net_conns_str': net_conns_str,
            'conn_summary': conn_summary,
        }

        # 运行时长格式化
        uptime = proc_detail['uptime']
        if uptime < 60:
            proc_detail['uptime_str'] = f'{uptime:.0f}秒'
        elif uptime < 3600:
            proc_detail['uptime_str'] = f'{uptime/60:.1f}分钟'
        elif uptime < 86400:
            proc_detail['uptime_str'] = f'{uptime/3600:.1f}小时'
        else:
            proc_detail['uptime_str'] = f'{uptime/86400:.1f}天'

        # 高危检测
        is_risky, risk_level, risk_reasons = _detect_high_risk(proc_detail)
        proc_detail['is_risky'] = is_risky
        proc_detail['risk_level'] = risk_level
        proc_detail['risk_reasons'] = risk_reasons
        proc_detail['risk_reasons_str'] = '; '.join(risk_reasons) if risk_reasons else ''

        processes.append(proc_detail)

    # 按启动时间排序
    processes.sort(key=lambda x: x['start_timestamp'] or 0)
    return processes


def _format_bytes(b):
    """格式化字节数"""
    if b == 0:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(b) < 1024:
            return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} PB'


def get_system_boot_info():
    """获取系统启动信息"""
    if psutil is None:
        raise ImportError('psutil is required')

    boot_time = psutil.boot_time()
    now = time.time()
    uptime = now - boot_time

    # 从 /proc/uptime 获取更精确的uptime
    proc_uptime = uptime
    try:
        with open('/proc/uptime', 'r') as f:
            proc_uptime = float(f.read().split()[0])
    except (FileNotFoundError, ValueError, IndexError):
        pass

    # 从 who -b 获取启动时间
    who_boot = ''
    try:
        r = subprocess.run(['who', '-b'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            who_boot = r.stdout.strip()
    except Exception:
        pass

    # systemd 启动时间
    systemd_boot = ''
    try:
        r = subprocess.run(['systemd-analyze'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            systemd_boot = r.stdout.strip()
    except Exception:
        pass

    # 用户登录信息
    users = []
    try:
        r = subprocess.run(['who'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.strip().split('\n'):
                if line.strip():
                    users.append(line.strip())
    except Exception:
        pass

    uptime_str = ''
    if uptime < 60:
        uptime_str = f'{uptime:.0f}秒'
    elif uptime < 3600:
        uptime_str = f'{uptime/60:.1f}分钟'
    elif uptime < 86400:
        uptime_str = f'{uptime/3600:.1f}小时'
    else:
        days = int(uptime // 86400)
        hours = (uptime % 86400) / 3600
        uptime_str = f'{days}天{hours:.1f}小时'

    return {
        'boot_time': boot_time,
        'boot_time_str': datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S'),
        'uptime': uptime,
        'uptime_str': uptime_str,
        'proc_uptime': proc_uptime,
        'who_boot': who_boot,
        'systemd_analyze': systemd_boot,
        'login_users': users,
    }


def get_process_summary(processes=None):
    """获取进程统计摘要"""
    if processes is None:
        processes = get_all_processes()

    total = len(processes)
    by_category = defaultdict(int)
    by_user = defaultdict(int)
    risky_count = 0
    has_network = 0
    has_schedule = 0
    listening_total = set()

    for p in processes:
        by_category[p['category']] += 1
        by_user[p['username']] += 1
        if p['is_risky']:
            risky_count += 1
        if p['network_connections']:
            has_network += 1
        if p['is_cron'] or p['is_systemd_timer'] or p['is_rc_local'] or p['is_initd']:
            has_schedule += 1
        listening_total.update(p['listening_ports'])

    return {
        'total_processes': total,
        'by_category': dict(by_category),
        'by_user': dict(by_user),
        'risky_count': risky_count,
        'has_network': has_network,
        'has_schedule': has_schedule,
        'listening_ports': sorted(listening_total),
        'listening_ports_count': len(listening_total),
    }
