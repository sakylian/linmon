#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
net_monitor.py — 网络连接监控模块
功能：采集网络连接列表（传送数据量/数据类型/对端OS/发起时间/频率）
"""

import os
import sys
import re
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

from .geo_locator import (
    GeoLocator, is_private_ip, is_valid_public_ip,
    classify_port, guess_remote_os, resolve_coordinates, cdn_lookup
)
from .proc_monitor import (
    _parse_proc_net_tcp, _parse_proc_net_tcp6, TCP_STATES,
    _get_pid_socket_inodes, _read_proc_stat, _read_proc_status,
    _read_proc_cmdline, _uid_to_username,
    _get_psutil_connections_cached,
)

logger = logging.getLogger(__name__)

# 当前是否运行在 macOS (Darwin)
IS_MACOS = sys.platform == 'darwin'

# 地理高风险地区外连判定配置（由 webserver / CLI 注入，默认关闭以避免误报）
_GEO_RISK = {'enabled': False, 'regions': []}


def configure_geo_risk(enabled, regions=None):
    """配置"高风险地区外连"本地规则。默认关闭。"""
    _GEO_RISK['enabled'] = bool(enabled)
    _GEO_RISK['regions'] = list(regions or [])


def start_frequency_sampler(interval=30):
    """启动后台线程周期性采集外连样本，使连接频率分析真正生效。"""
    import threading

    def _loop():
        while True:
            try:
                sample_connections()
            except Exception:
                pass
            threading.Event().wait(interval)

    t = threading.Thread(target=_loop, name='linmon-freq-sampler', daemon=True)
    t.start()
    return t


def _run_psutil_connections():
    """macOS 下用 psutil 采集网络连接，返回与 ss 结构一致的连接列表。

    macOS 非 root 下 psutil.net_connections() 会因个别进程 AccessDenied
    导致整批抛异常；改为逐进程 proc.connections() 采集，跳过拒绝访问的进程。
    """
    conns = []
    if psutil is None:
        return conns
    for proc in psutil.process_iter(['pid']):
        pid = proc.pid
        try:
            raw_conns = proc.connections(kind='inet')
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        # 进程名（用于展示）
        try:
            pname = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pname = ''
        for c in raw_conns:
            laddr = c.laddr
            raddr = c.raddr
            proto = 'tcp6' if c.family == socket.AF_INET6 else 'tcp'
            if c.type == socket.SOCK_DGRAM:
                proto = 'udp6' if c.family == socket.AF_INET6 else 'udp'
            local_ip = laddr.ip if laddr else '0.0.0.0'
            local_port = int(laddr.port) if laddr else 0
            remote_ip = raddr.ip if raddr else '0.0.0.0'
            remote_port = int(raddr.port) if raddr else 0
            state = c.status or 'UNKNOWN'
            process = f'{pname}({pid})' if pname else str(pid)
            conns.append({
                'protocol': proto,
                'state': state,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'process': process,
                'timer': '',
                'skmem': '',
                'inode': getattr(c, 'fd', None) or '',
                'raw': '',
            })
    return conns


def _run_ss_command():
    """运行 ss 命令获取更详细的连接信息（含 timer/process）"""
    # macOS 无 ss，改用 psutil
    if IS_MACOS:
        return _run_psutil_connections()

    connections = []
    try:
        r = subprocess.run(
            ['ss', '-tunape', '-o', '-m'],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0:
            return connections

        lines = r.stdout.strip().split('\n')
        if len(lines) < 2:
            return connections

        for line in lines[1:]:
            try:
                # 跳过续行（skmem/timer 等，以 tab 开头）
                if line.startswith('\t') or line.startswith(' '):
                    continue
                parts = line.split()
                if len(parts) < 6:
                    continue

                proto = parts[0]  # tcp, udp, tcp6, udp6
                # ss 输出格式: Netid State Recv-Q Send-Q Local:Port Peer:Port Process...
                # parts[0]=Netid, parts[1]=State, parts[2]=Recv-Q, parts[3]=Send-Q
                # parts[4]=Local Address:Port, parts[5]=Peer Address:Port
                state = parts[1]
                idx = 4  # Local Address 在 parts[4]

                # local:remote
                if idx + 1 >= len(parts):
                    continue
                local_addr = parts[idx]
                remote_addr = parts[idx + 1]
                idx += 2

                # 解析地址端口
                local_ip, local_port = _parse_addr(local_addr)
                remote_ip, remote_port = _parse_addr(remote_addr)

                # 解析进程信息 (users:((\"proc\",pid=123,fd=4)))
                process_info = ''
                timer_info = ''
                mem_info = ''
                inode = ''
                for extra in parts[idx:]:
                    if extra.startswith('users:'):
                        # 提取进程名和PID
                        import re
                        m = re.search(r'\(\("([^"]+)",pid=(\d+)', extra)
                        if m:
                            process_info = f'{m.group(1)}({m.group(2)})'
                    elif extra.startswith('timer:'):
                        timer_info = extra[6:]
                    elif extra.startswith('skmem:'):
                        mem_info = extra[6:]
                    elif extra.startswith('ino:'):
                        inode = extra[4:]

                connections.append({
                    'protocol': proto,
                    'state': state,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'process': process_info,
                    'timer': timer_info,
                    'skmem': mem_info,
                    'inode': inode,
                    'raw': line,
                })
            except Exception as e:
                logger.debug(f'ss parse error on line: {e}')
                continue
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except Exception as e:
        logger.debug(f'ss command error: {e}')

    return connections


def _parse_addr(addr_str):
    """解析地址字符串，返回 (ip, port)"""
    # 格式: 192.168.1.1:80 或 [::1]:80 或 *:80 或 0.0.0.0:*
    if ':' not in addr_str:
        return addr_str, 0

    if addr_str.startswith('['):
        # IPv6: [::1]:80 或 [::]:*
        end = addr_str.rfind(']')
        ip = addr_str[1:end]
        port_str = addr_str[end+2:] if end + 2 < len(addr_str) else '0'
        try:
            port = int(port_str)
        except ValueError:
            port = 0
    elif addr_str.count(':') > 1:
        # IPv6 无方括号: ::1:80 (ss 不会这样输出，但以防万一)
        # 也可能是 127.0.0.53%lo:53 这种带接口名的
        last_colon = addr_str.rfind(':')
        ip = addr_str[:last_colon]
        port_str = addr_str[last_colon+1:]
        try:
            port = int(port_str)
        except ValueError:
            ip = addr_str
            port = 0
    else:
        ip, port_str = addr_str.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 0

    if ip == '*':
        ip = '0.0.0.0'
    # 清理 IP 中的接口名后缀 (如 127.0.0.53%lo → 127.0.0.53)
    if '%' in ip:
        ip = ip.split('%')[0]
    return ip, port


def _get_conn_data_volume(inode):
    """通过 /proc/net/netstat 和 ss 获取连接的数据量估算"""
    # ss -o 的 timer 字段包含重传队列信息
    # /proc/net/snmp 有全局统计
    # 这里返回基于 /proc 的估算
    return {'bytes_sent': 0, 'bytes_recv': 0}


def _get_process_io_stats(pid):
    """获取进程IO统计"""
    # macOS 无 /proc，用 psutil.io_counters / memory 估算
    if IS_MACOS:
        if psutil is None or not pid:
            return {}
        try:
            p = psutil.Process(pid)
            io = p.io_counters()
            if io:
                return {
                    'read_bytes': io.read_bytes,
                    'write_bytes': io.write_bytes,
                }
        except (psutil.Error, AttributeError, OSError):
            pass
        return {}
    try:
        io_stats = {}
        with open(f'/proc/{pid}/io', 'r') as f:
            for line in f:
                key, val = line.strip().split(':')
                io_stats[key.strip()] = int(val.strip())
        return io_stats
    except (FileNotFoundError, PermissionError, ValueError):
        return {}


def _get_connection_age(timer_str):
    """从 ss timer 字段解析连接年龄"""
    if not timer_str:
        return None, None

    # timer 格式: (1.234ms,0) 或 (keepalive,30s,0)
    parts = timer_str.strip('()').split(',')
    if not parts:
        return None, None

    first = parts[0].strip()
    # 连接年龄通常在第一个字段，格式如 1.234ms / 5.678s
    age_seconds = None
    try:
        if first.endswith('ms'):
            age_seconds = float(first[:-2]) / 1000
        elif first.endswith('s'):
            age_seconds = float(first[:-1])
        elif first.endswith('m'):
            age_seconds = float(first[:-1]) * 60
        elif first.endswith('h'):
            age_seconds = float(first[:-1]) * 3600
        else:
            age_seconds = float(first)
    except ValueError:
        pass

    # keepalive/重传 信息
    info = timer_str
    return age_seconds, info


def _estimate_remote_os(remote_ip):
    """通过 ping TTL 估算对端操作系统"""
    if is_private_ip(remote_ip):
        return '内网(无法推断)'

    try:
        # macOS 的 ping -W 单位是毫秒且语义不同，用 -t（超时秒）代替
        cmd = ['ping', '-c', '1', '-t', '2', remote_ip] if IS_MACOS \
            else ['ping', '-c', '1', '-W', '2', remote_ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            # 提取 ttl=X (macOS 输出 ttl= / time=)
            import re
            m = re.search(r'ttl=(\d+)', r.stdout)
            if m:
                ttl = int(m.group(1))
                return guess_remote_os(ttl)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return '未知(不可达或ICMP被过滤)'


def _classify_data_type(local_port, remote_port, protocol):
    """推断传送数据类型"""
    from .geo_locator import classify_port

    # 优先使用远程端口判断
    proto_name, risk = classify_port(remote_port, protocol)
    if proto_name != '注册端口' and proto_name != '动态端口' and proto_name != '系统端口':
        return proto_name, risk

    # 再看本地端口
    proto_name, risk = classify_port(local_port, protocol)
    return proto_name, risk


def _determine_direction(local_port, remote_port):
    """判断连接方向"""
    if remote_port == 0:
        return 'listen'
    if remote_port in (80, 443, 53, 25, 22, 21, 3306, 5432, 6379, 8080, 8443):
        return 'outbound'
    if local_port in (80, 443, 53, 25, 22, 21, 3306, 5432, 6379, 8080, 8443):
        return 'inbound'
    if local_port < 1024 and remote_port >= 1024:
        return 'inbound'
    if remote_port < 1024 and local_port >= 1024:
        return 'outbound'
    return 'unknown'


def _assess_connection_risk(conn_info):
    """评估连接风险等级"""
    reasons = []

    remote_ip = conn_info.get('remote_ip', '')
    remote_port = conn_info.get('remote_port', 0)
    local_port = conn_info.get('local_port', 0)
    proto_name, risk = conn_info.get('data_type_info', ('未知', 'low'))
    direction = conn_info.get('direction', 'unknown')
    process = conn_info.get('process', '')
    state = conn_info.get('state', '')

    # LISTEN 状态只提示，不判高危（监听端口本身是服务行为，需结合进程判断）
    if direction == 'listen' or state == 'LISTEN':
        # 监听端口仅对可疑进程标记
        if process:
            proc_lower = process.lower()
            if any(name in proc_lower for name in ('nc', 'ncat', 'socat', 'python', 'perl', 'bash', 'sh')):
                reasons.append(f'疑似后门监听: {process} 监听 {local_port}')
        level = 'high' if reasons else 'low'
        return level, reasons

    # 高危端口
    if risk == 'high':
        reasons.append(f'高危端口: {remote_port} ({proto_name})')

    # 可疑端口
    suspicious_ports = [4444, 1337, 8444, 29999, 10080, 10443]
    if remote_port in suspicious_ports or local_port in suspicious_ports:
        reasons.append(f'可疑后门端口: {remote_port}')

    # 异常外连到高风险地区（本地规则，需显式启用；默认关闭避免误报）
    if _GEO_RISK['enabled']:
        geo_str = conn_info.get('geo', {}).get('geo_str', '')
        country = conn_info.get('geo', {}).get('country', '')
        for region in _GEO_RISK['regions']:
            if region and (region in country or region in geo_str):
                reasons.append(f'连接至高风险地区: {region}')
                break

    # SSH暴力破解迹象
    if remote_port == 22 and direction == 'inbound':
        reasons.append('SSH入站连接(需确认合法性)')

    # 反弹Shell特征
    if process:
        proc_lower = process.lower()
        if any(name in proc_lower for name in ('bash', 'sh', 'python', 'perl', 'nc', 'socat')):
            if direction == 'outbound' and is_valid_public_ip(remote_ip):
                reasons.append(f'疑似反弹Shell: {process} 外连到 {remote_ip}')

    # 非标准端口
    if remote_port > 49151 and direction == 'outbound' and is_valid_public_ip(remote_ip):
        reasons.append(f'外连到非标准高端口: {remote_port}')

    level = 'high' if any('后门' in r or '反弹' in r or '高危' in r for r in reasons) else \
            'medium' if reasons else 'low'

    return level, reasons


# 连接频率采样缓存
_connection_samples = []


def sample_connections():
    """采样当前连接状态（用于频率分析）"""
    global _connection_samples
    now = time.time()
    conns = _run_ss_command()

    # 提取外连目标
    external_conns = []
    for c in conns:
        if c['remote_ip'] and is_valid_public_ip(c['remote_ip']):
            key = f"{c['remote_ip']}:{c['remote_port']}"
            external_conns.append({
                'key': key,
                'remote_ip': c['remote_ip'],
                'remote_port': c['remote_port'],
                'process': c['process'],
                'timestamp': now,
            })

    _connection_samples.append({
        'time': now,
        'connections': external_conns,
    })

    # 只保留最近24小时的样本
    cutoff = now - 86400
    _connection_samples = [s for s in _connection_samples if s['time'] > cutoff]

    # 限制最大样本数
    if len(_connection_samples) > 1000:
        _connection_samples = _connection_samples[-1000:]

    return external_conns


def get_connection_frequency(remote_ip=None, remote_port=None):
    """获取连接频率统计"""
    global _connection_samples
    if not _connection_samples:
        return {
            'sample_count': 0,
            'first_seen': None,
            'last_seen': None,
            'avg_interval': None,
            'frequency_desc': '无采样数据(需持续监控)',
        }

    matches = []
    for sample in _connection_samples:
        for conn in sample['connections']:
            if remote_ip and conn['remote_ip'] != remote_ip:
                continue
            if remote_port and conn['remote_port'] != remote_port:
                continue
            matches.append(sample['time'])

    if not matches:
        return {
            'sample_count': len(_connection_samples),
            'first_seen': None,
            'last_seen': None,
            'avg_interval': None,
            'frequency_desc': '在采样期间未检测到此连接',
        }

    matches.sort()
    first = matches[0]
    last = matches[-1]
    count = len(matches)
    duration = last - first if count > 1 else 0

    if count > 1:
        intervals = [matches[i+1] - matches[i] for i in range(len(matches)-1)]
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 60:
            freq_desc = f'高频连接(平均间隔{avg_interval:.0f}秒, {count}次)'
        elif avg_interval < 300:
            freq_desc = f'中频连接(平均间隔{avg_interval/60:.1f}分钟, {count}次)'
        elif avg_interval < 3600:
            freq_desc = f'低频连接(平均间隔{avg_interval/60:.1f}分钟, {count}次)'
        else:
            freq_desc = f'偶发连接(平均间隔{avg_interval/3600:.1f}小时, {count}次)'
    else:
        avg_interval = None
        freq_desc = f'仅出现1次(首次:{datetime.fromtimestamp(first).strftime("%H:%M:%S")})'

    return {
        'sample_count': len(_connection_samples),
        'match_count': count,
        'first_seen': datetime.fromtimestamp(first).strftime('%Y-%m-%d %H:%M:%S'),
        'last_seen': datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M:%S'),
        'avg_interval': avg_interval,
        'frequency_desc': freq_desc,
    }


def get_all_connections(qqwry_path=None, include_internal=False, detect_os=False):
    """
    获取所有网络连接的详细信息
    返回 list[dict]
    """
    # 使用 ss 命令获取详细连接信息（macOS 用 psutil）
    ss_conns = _run_ss_command()

    # 同时解析 /proc/net/tcp 获取 kernel 级连接（仅 Linux）
    proc_conns = []
    inode_to_pid = {}
    if not IS_MACOS:
        proc_conns = _parse_proc_net_tcp() + _parse_proc_net_tcp6()

        # 构建 inode → pid 映射
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            pid_int = int(pid)
            inodes = _get_pid_socket_inodes(pid_int)
            for inode in inodes:
                inode_to_pid[inode] = pid_int
    else:
        # macOS: 用 psutil 连接缓存补齐 pid → 连接
        # (psutil 的 pid 关联比 inode 更直接；这里仅用于 proc_conns 为空时的兜底)
        pass

    connections = []
    seen_keys = set()
    # 去重合并用的聚合表: key(remote_ip:remote_port+process+direction) → conn_info
    agg_map = {}
    # inode → pid 映射已在上面构建，这里做进程信息缓存
    pid_cache = {}

    def _get_pid_info(pid):
        """获取进程信息（带缓存）"""
        if pid in pid_cache:
            return pid_cache[pid]
        info = {'name': '', 'cmdline': '', 'user': ''}
        if pid:
            if IS_MACOS and psutil is not None:
                # macOS: 用 psutil 获取进程信息
                try:
                    p = psutil.Process(pid)
                    info['name'] = p.name() or ''
                    info['cmdline'] = ' '.join(p.cmdline() or [])
                    info['user'] = p.username() or 'unknown'
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            else:
                stat = _read_proc_stat(pid)
                if stat:
                    info['name'] = stat.get('comm', '')
                    info['cmdline'] = _read_proc_cmdline(pid)
                stat_info = _read_proc_status(pid)
                uid = stat_info.get('Uid', '0').split()[0] if 'Uid' in stat_info else '0'
                info['user'] = _uid_to_username(int(uid)) if uid.isdigit() else 'unknown'
        pid_cache[pid] = info
        return info

    # 处理 ss 命令的输出
    for sc in ss_conns:
        remote_ip = sc['remote_ip']
        remote_port = sc['remote_port']

        # 过滤
        if not include_internal and remote_ip and is_private_ip(remote_ip):
            if remote_ip not in ('0.0.0.0', '::') and remote_port == 0:
                continue

        # 去重 (同一连接只保留一次)
        key = f"{sc['protocol']}:{sc['local_ip']}:{sc['local_port']}:{remote_ip}:{remote_port}"
        if key in seen_keys:
            continue
        seen_keys.add(key)

        # 数据类型
        data_type, risk = _classify_data_type(sc['local_port'], remote_port, sc['protocol'])

        # 方向
        direction = _determine_direction(sc['local_port'], remote_port)

        # 连接时长
        age_seconds, timer_info = _get_connection_age(sc.get('timer', ''))

        # IP 归属地
        geo = {'ip': remote_ip, 'country': '', 'area': '', 'geo_str': '',
               'lng': None, 'lat': None}
        if remote_ip and is_valid_public_ip(remote_ip):
            geo = GeoLocator.lookup_ip(remote_ip)

        # 对端 OS 推断
        remote_os = '未知'
        if detect_os and remote_ip and is_valid_public_ip(remote_ip) and remote_port > 0:
            remote_os = _estimate_remote_os(remote_ip)

        # 频率
        freq = get_connection_frequency(remote_ip, remote_port) if remote_port > 0 else {}

        # 进程信息: 优先 ss 的 users: 字段（已解析为 name(pid) 格式），其次用 inode → pid 映射补充
        pid = 0
        proc_name = ''
        proc_cmdline = ''
        proc_user = ''
        if sc['process']:
            m = re.match(r'^(.+)\((\d+)\)$', sc['process'])
            if m:
                proc_name = m.group(1)
                pid = int(m.group(2))
        if not pid and sc.get('inode') and sc['inode'] in inode_to_pid:
            pid = inode_to_pid[sc['inode']]
        if pid:
            pinfo = _get_pid_info(pid)
            proc_name = proc_name or pinfo['name']
            proc_cmdline = proc_cmdline or pinfo['cmdline']
            proc_user = pinfo['user']

        # 进程 IO 数据量
        io_stats = _get_process_io_stats(pid) if pid else {}
        bytes_sent = io_stats.get('write_bytes', 0)
        bytes_recv = io_stats.get('read_bytes', 0)

        conn_info = {
            'protocol': sc['protocol'],
            'state': sc['state'],
            'local_ip': sc['local_ip'],
            'local_port': sc['local_port'],
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'process': proc_name,
            'pid': pid,
            'process_cmdline': proc_cmdline,
            'process_user': proc_user,
            'direction': direction,
            'data_type': data_type,
            'data_type_info': (data_type, risk),
            'remote_os': remote_os,
            'age_seconds': age_seconds,
            'timer_info': timer_info,
            'geo': geo,
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'bytes_sent_str': _format_bytes(bytes_sent),
            'bytes_recv_str': _format_bytes(bytes_recv),
            'frequency': freq,
            'frequency_desc': freq.get('frequency_desc', ''),
            'is_public': is_valid_public_ip(remote_ip),
            'is_private': is_private_ip(remote_ip),
        }

        # 年龄格式化
        if age_seconds is not None:
            if age_seconds < 60:
                conn_info['age_str'] = f'{age_seconds:.1f}秒'
            elif age_seconds < 3600:
                conn_info['age_str'] = f'{age_seconds/60:.1f}分钟'
            else:
                conn_info['age_str'] = f'{age_seconds/3600:.1f}小时'
        else:
            conn_info['age_str'] = '未知'

        # 风险评估
        risk_level, risk_reasons = _assess_connection_risk(conn_info)
        conn_info['risk_level'] = risk_level
        conn_info['risk_reasons'] = risk_reasons
        conn_info['risk_reasons_str'] = '; '.join(risk_reasons)

        # 合并去重: 活跃连接按 (remote_ip:remote_port + 进程 + 方向) 合并，LISTEN 不合并
        if direction != 'listen' and remote_port > 0:
            agg_key = f"{remote_ip}:{remote_port}|{proc_name}|{direction}|{sc['protocol']}"
            if agg_key in agg_map:
                agg_map[agg_key]['conn_count'] += 1
                agg_map[agg_key]['local_ports'].append(f"{sc['local_ip']}:{sc['local_port']}")
                continue
            conn_info['conn_count'] = 1
            conn_info['local_ports'] = [f"{sc['local_ip']}:{sc['local_port']}"]
            agg_map[agg_key] = conn_info
        connections.append(conn_info)

    # 按风险等级和远程IP排序
    risk_order = {'high': 0, 'medium': 1, 'low': 2}
    connections.sort(key=lambda x: (risk_order.get(x['risk_level'], 3), x['remote_ip']))

    return connections


def get_network_summary(connections=None, qqwry_path=None):
    """获取网络连接统计摘要"""
    if connections is None:
        connections = get_all_connections(qqwry_path=qqwry_path)

    total = len(connections)
    by_protocol = defaultdict(int)
    by_direction = defaultdict(int)
    by_risk = defaultdict(int)
    by_data_type = defaultdict(int)
    public_ips = set()
    countries = set()
    listening_ports = set()

    for c in connections:
        by_protocol[c['protocol']] += 1
        by_direction[c['direction']] += 1
        by_risk[c['risk_level']] += 1
        by_data_type[c['data_type']] += 1
        if c['is_public']:
            public_ips.add(c['remote_ip'])
            if c['geo'].get('country'):
                countries.add(c['geo']['country'])
        if c['direction'] == 'listen' and c['local_port'] > 0:
            listening_ports.add(c['local_port'])

    return {
        'total_connections': total,
        'by_protocol': dict(by_protocol),
        'by_direction': dict(by_direction),
        'by_risk': dict(by_risk),
        'by_data_type': dict(by_data_type),
        'public_ip_count': len(public_ips),
        'country_count': len(countries),
        'listening_ports': sorted(listening_ports),
        'listening_ports_count': len(listening_ports),
    }


def _format_bytes(b):
    if b == 0:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(b) < 1024:
            return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} PB'


def run_traceroute(target, max_hops=30, timeout=5):
    """执行 traceroute 路由跟踪"""
    import shutil as sh

    hops = []
    cmd = None
    if sh.which('traceroute'):
        # macOS/BSD traceroute 默认每跳 3 次探测，-q 1 减为 1 次以大幅缩短耗时
        if IS_MACOS:
            cmd = ['traceroute', '-m', str(max_hops), '-w', str(timeout), '-q', '1', target]
        else:
            cmd = ['traceroute', '-m', str(max_hops), '-w', str(timeout), target]
    elif sh.which('mtr'):
        cmd = ['mtr', '--report', '--report-cycles', '1', target]
    elif sh.which('tracepath'):
        cmd = ['tracepath', target]

    if not cmd:
        return {'error': '未找到 traceroute/mtr/tracepath 命令，请安装: sudo apt install traceroute 或 sudo yum install traceroute'}

    try:
        # macOS -q 1 后每跳最多 timeout 秒；Linux 仍为 3 次。取两者上限 + 缓冲
        probes_per_hop = 1 if IS_MACOS else 3
        total_timeout = max_hops * timeout * probes_per_hop + 10
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=total_timeout)
        output = r.stdout
    except subprocess.TimeoutExpired:
        return {'error': f'traceroute 超时 ({target})'}
    except FileNotFoundError:
        return {'error': 'traceroute 命令不可用'}

    import re
    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue
        # 跳过表头/汇总行：traceroute 头、tracepath 的 pmtu / Too many hops / Resume
        if line.startswith('traceroute') or line.startswith('Too many hops') \
           or line.startswith('Resume:') or line.startswith('pmtu'):
            continue

        # 跳号：traceroute/mtr 为行首纯数字+空格；tracepath 为 "1:" 或 "1?:"
        m = re.match(r'^\s*(\d+)\??(?::|\s+)\s*(.*)$', line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2)

        # tracepath 的 "no reply" 跳：仍记录一跳，便于展示路径长度
        if 'no reply' in rest:
            hops.append({'hop': hop_num, 'ip': '*', 'hostname': '', 'rtt_ms': None, 'geo': None})
            continue

        # IP：优先 (1.2.3.4) 形式，否则裸 IP（tracepath 经常只给裸 IP）
        ip_addr = None
        ipm = re.search(r'\(([\d.]+)\)', rest) or re.search(r'\(([\da-fA-F:]+)\)', rest)
        if ipm:
            ip_addr = ipm.group(1)
        else:
            bare = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', rest)
            if bare:
                ip_addr = bare.group(1)

        # 主机名：括号内 IP 前的文本，否则取首个非 rtt 词
        hostname = ''
        if ipm:
            hostname = rest[:rest.index(ipm.group(0))].strip()
        else:
            toks = rest.split()
            if toks and not re.match(r'\d+\.?\d*ms', toks[0]):
                hostname = toks[0]

        rttm = re.search(r'(\d+\.?\d*)\s*ms', rest)
        rtt = float(rttm.group(1)) if rttm else None

        # IP 归属地 + CDN 判断（使用 hop 主机名）
        geo = None
        if ip_addr and is_valid_public_ip(ip_addr):
            geo = GeoLocator.lookup_ip(ip_addr, hostname=hostname or None)

        hops.append({
            'hop': hop_num,
            'ip': ip_addr or '*',
            'hostname': hostname,
            'rtt_ms': rtt,
            'geo': geo,
        })

    return {'target': target, 'hops': hops}


def _pick_macos_iface():
    """选择一个可用的 macOS 网络接口用于抓包（macOS 无 any 接口）。"""
    if psutil is not None:
        try:
            stats = psutil.net_if_stats()
            for name in stats:
                # 选择有 IPv4 地址且 up 的接口，排除环回优先考虑
                if name == 'lo0':
                    continue
                return name
        except (psutil.Error, OSError):
            pass
    # 回退：ifconfig 找第一个非 lo0 接口
    try:
        r = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
        for line in r.stdout.split('\n'):
            if line and not line.startswith(' ') and not line.startswith('\t'):
                iface = line.split(':')[0].strip()
                if iface and iface != 'lo0':
                    return iface
    except Exception:
        pass
    return 'en0'


def _get_local_ip_addrs():
    """获取本机所有 IPv4 接口地址，用于判定抓包方向（发送/接收）"""
    ips = set()
    # macOS: 用 psutil 或系统命令获取接口地址
    if IS_MACOS:
        if psutil is not None:
            try:
                for _, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        if a.family == socket.AF_INET and a.address:
                            ips.add(a.address.split('%')[0])
                return ips
            except (psutil.Error, OSError):
                pass
        try:
            r = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
            for m in re.finditer(r'inet\s+(\d{1,3}(?:\.\d{1,3}){3})', r.stdout):
                ips.add(m.group(1))
        except Exception:
            pass
        return ips

    # Linux: /sys/class/net + fcntl.ioctl
    import socket, fcntl, struct, os
    try:
        for iface in os.listdir('/sys/class/net'):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface[:15].encode()))
                ips.add(socket.inet_ntoa(info[20:24]))
            except Exception:
                pass
            finally:
                s.close()
    except Exception:
        pass
    return ips


# 常见顶级域白名单：用于从抓包载荷中筛除形如 "e.g." 的误匹配
_TLDS = {
    'com', 'net', 'org', 'cn', 'io', 'edu', 'gov', 'co', 'uk', 'de', 'fr', 'jp',
    'ru', 'us', 'tv', 'me', 'app', 'dev', 'cloud', 'biz', 'info', 'name', 'pro',
    'xyz', 'top', 'vip', 'cc', 'hk', 'tw', 'kr', 'sg', 'in', 'au', 'br', 'ca',
}
_HOST_HEADER_RE = re.compile(r'Host:\s*([^\s/\r\n]+)', re.IGNORECASE)
_DOMAIN_RE = re.compile(
    # 首标签必须以字母开头，避免把 TLS SNI 长度前缀字节（如 "0.xx"）误并入域名
    r'[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9-]{1,63})+\.('
    + '|'.join(_TLDS) + r')\b'
)


def _extract_hostname_from_payload(preview):
    """从 tcpdump -A 的 ASCII 载荷预览里提取域名（HTTP Host 头或 TLS SNI）。

    返回小写主机名（已去掉端口与结尾点），无则 None。仅用于本地 CDN 标注，
    不做任何外发。
    """
    if not preview:
        return None
    m = _HOST_HEADER_RE.search(preview)
    if m:
        host = m.group(1).strip().lower()
        return host.split(':')[0].rstrip('.')
    # TLS ClientHello 的 SNI 以可读 ASCII 出现在载荷中
    m = _DOMAIN_RE.search(preview)
    if m:
        cand = m.group(0).lower().rstrip('.')
        # 排除形如纯 IP 的误匹配
        if '.' in cand and not is_valid_public_ip(cand):
            return cand
    return None


def capture_traffic(remote_ip, remote_port=None, iface='any', count=60, timeout=8):
    """对指定远端 IP/端口抓包并做本地分析（不对外发送任何数据）。

    返回数据包级摘要：时间、源/目的、端口、TCP 标志、长度、方向、载荷预览，
    并汇总发送/接收字节与包数，按本地端口关联当前连接解析出对应进程。
    """
    import shutil as sh, subprocess as sp, re as _re

    if not (is_valid_public_ip(remote_ip) or is_private_ip(remote_ip)):
        return {'error': '无效的 IP 地址'}

    if sh.which('tcpdump'):
        tool = 'tcpdump'
    elif sh.which('tshark'):
        tool = 'tshark'
    else:
        return {'error': '未找到 tcpdump/tshark，请安装: sudo apt install tcpdump'}

    filt = 'host %s' % remote_ip
    if remote_port:
        filt += ' and port %d' % int(remote_port)
    # macOS 的 tcpdump 无 'any' 接口，需选一个实际接口；且 BSD 版不支持 -tttt（用 -tt）
    if IS_MACOS and (not iface or iface == 'any'):
        try:
            iface = _pick_macos_iface()
        except Exception:
            iface = ''
    if tool == 'tcpdump':
        ts_flag = '-tt' if IS_MACOS else '-tttt'
        # -n 不解析名称, 时间戳, -A 输出 ASCII 载荷预览, -s 0 全量, -c count 达到即退出
        cmd = ['tcpdump', '-i', iface, '-n', ts_flag, '-A', '-s', '0', '-c', str(count), filt]
    else:
        cmd = ['tshark', '-i', iface, '-c', str(count), '-f', filt]

    try:
        r = sp.run(cmd, capture_output=True, text=True, timeout=timeout + 20)
    except sp.TimeoutExpired:
        return {'error': '抓包超时（%ds），该连接当前可能无流量' % timeout}
    except FileNotFoundError:
        return {'error': '抓包命令不可用'}

    out = (r.stdout or '') + '\n' + (r.stderr or '')
    # 权限不足时给出明确提示
    if ('permission' in out.lower() or 'not have permission' in out.lower() or 'could not' in out.lower()) \
       and 'length' not in out:
        return {'error': '抓包需要 root 权限，请用 sudo 运行 linmon 的 Web 服务'}

    local_ips = _get_local_ip_addrs()
    # tcpdump 摘要行: "时间戳 IP src.port > dst.port: Flags [..], ..., length N"
    pkt_re = _re.compile(
        r'IP6?\s+([\d.a-fA-F:]+)\.(\d+)\s+>\s+([\d.a-fA-F:]+)\.(\d+):\s+Flags\s+\[([^\]]+)\],.*?length\s+(\d+)'
    )

    packets = []
    sent_bytes = recv_bytes = 0
    sent_pkts = recv_pkts = 0
    lines = out.split('\n')
    cur = None
    payload_buf = []

    def flush():
        nonlocal cur, payload_buf
        if cur is not None:
            raw = ''.join(payload_buf)
            # 仅保留可打印字符，截断预览，避免乱码/敏感内容过长
            preview = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in raw)[:120].strip()
            cur['payload_preview'] = preview
            packets.append(cur)
        cur = None
        payload_buf = []

    for ln in lines:
        mm = pkt_re.search(ln)
        if mm:
            flush()
            src, sport, dst, dport, flags, length = mm.groups()
            length = int(length)
            is_sent = src in local_ips
            is_recv = dst in local_ips
            ts = ln.split(' IP')[0].strip() if ' IP' in ln else ln.split(' IP6')[0].strip()
            cur = {
                'time': ts,
                'src': src, 'sport': int(sport),
                'dst': dst, 'dport': int(dport),
                'flags': flags, 'len': length,
                'dir': 'sent' if is_sent else ('recv' if is_recv else 'other'),
            }
            if is_sent:
                sent_bytes += length; sent_pkts += 1
            elif is_recv:
                recv_bytes += length; recv_pkts += 1
            payload_buf = []
        elif cur is not None and ln.strip():
            payload_buf.append(ln)
    flush()

    # 按本地端口关联当前连接，解析出对应进程
    proc_map = {}
    try:
        for c in get_all_connections():
            lp = c.get('local_port')
            if lp:
                proc_map[lp] = {
                    'pid': c.get('pid'),
                    'name': c.get('process'),
                    'cmdline': c.get('process_cmdline'),
                    'user': c.get('process_user'),
                }
    except Exception:
        pass
    process = None
    for p in packets:
        if p['dir'] == 'sent' and p['sport'] in proc_map:
            process = proc_map[p['sport']]; break
    if process is None:
        for p in packets:
            if p['dir'] == 'recv' and p['dport'] in proc_map:
                process = proc_map[p['dport']]; break

    # 从抓包载荷提取 SNI/Host 域名，用于 CDN 标注（HTTPS 无需反向 DNS）
    sni = None
    for p in packets:
        if p['dir'] in ('sent', 'other') and p.get('payload_preview'):
            hn = _extract_hostname_from_payload(p['payload_preview'])
            if hn:
                sni = hn
                break
    cdn = None
    geo = None
    if sni:
        try:
            cdn = cdn_lookup(sni)
            geo = GeoLocator.lookup_ip(remote_ip, hostname=sni)
        except Exception:
            pass

    result = {
        'target': '%s:%s' % (remote_ip, remote_port) if remote_port else remote_ip,
        'tool': tool,
        'count': len(packets),
        'total_bytes': sent_bytes + recv_bytes,
        'sent_bytes': sent_bytes,
        'recv_bytes': recv_bytes,
        'sent_packets': sent_pkts,
        'recv_packets': recv_pkts,
        'process': process,
        'local_ips': sorted(local_ips),
        'packets': packets,
        'note': '本地抓包分析，数据仅在本机展示，未对外发送',
    }
    if sni:
        result['sni'] = sni
    if cdn:
        result['cdn'] = cdn
    if geo:
        result['geo'] = geo
    return result
