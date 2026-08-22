#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
net_monitor.py — 网络连接监控模块
功能：采集网络连接列表（传送数据量/数据类型/对端OS/发起时间/频率）
"""

import os
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
    classify_port, guess_remote_os, resolve_coordinates
)
from .proc_monitor import (
    _parse_proc_net_tcp, _parse_proc_net_tcp6, TCP_STATES,
    _get_pid_socket_inodes, _read_proc_stat, _read_proc_status,
    _read_proc_cmdline, _uid_to_username
)

logger = logging.getLogger(__name__)

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


def _run_ss_command():
    """运行 ss 命令获取更详细的连接信息（含 timer/process）"""
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
        r = subprocess.run(
            ['ping', '-c', '1', '-W', '2', remote_ip],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            # 提取 ttl=X
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
    # 使用 ss 命令获取详细连接信息
    ss_conns = _run_ss_command()

    # 同时解析 /proc/net/tcp 获取 kernel 级连接
    proc_conns = _parse_proc_net_tcp() + _parse_proc_net_tcp6()

    # 构建 inode → pid 映射
    inode_to_pid = {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        pid_int = int(pid)
        inodes = _get_pid_socket_inodes(pid_int)
        for inode in inodes:
            inode_to_pid[inode] = pid_int

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
        cmd = ['traceroute', '-m', str(max_hops), '-w', str(timeout), target]
    elif sh.which('mtr'):
        cmd = ['mtr', '--report', '--report-cycles', '1', target]
    elif sh.which('tracepath'):
        cmd = ['tracepath', target]

    if not cmd:
        return {'error': '未找到 traceroute/mtr/tracepath 命令，请安装: sudo apt install traceroute 或 sudo yum install traceroute'}

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * timeout + 10)
        output = r.stdout
    except subprocess.TimeoutExpired:
        return {'error': f'traceroute 超时 ({target})'}
    except FileNotFoundError:
        return {'error': 'traceroute 命令不可用'}

    import re
    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('traceroute'):
            continue

        # traceroute 输出格式: 1  192.168.1.1 (192.168.1.1)  0.5ms  0.4ms  0.3ms
        # mtr 输出格式: 1|--192.168.1.1  0.0  0.0  0.0
        parts = re.split(r'\s+', line)

        hop_num = None
        ip_addr = None
        rtt = None
        hostname = ''

        try:
            # 标准traceroute格式
            if parts[0].isdigit():
                hop_num = int(parts[0])
                idx = 1
                # 跳过空字段
                while idx < len(parts) and not parts[idx]:
                    idx += 1
                if idx < len(parts):
                    ip_or_name = parts[idx]
                    ip_match = re.search(r'\(([\d.]+)\)', line) or re.search(r'\(([\da-fA-F:]+)\)', line)
                    if ip_match:
                        ip_addr = ip_match.group(1)
                        hostname = ip_or_name if ip_or_name != f'({ip_addr})' else ''
                    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_or_name):
                        ip_addr = ip_or_name
                    idx += 1
                    rtt_match = re.search(r'(\d+\.?\d*)\s*ms', line)
                    if rtt_match:
                        rtt = float(rtt_match.group(1))
        except (ValueError, IndexError):
            pass

        if hop_num is not None:
            # IP 归属地
            geo = None
            if ip_addr and is_valid_public_ip(ip_addr):
                geo = GeoLocator.lookup_ip(ip_addr)
            hops.append({
                'hop': hop_num,
                'ip': ip_addr or '*',
                'hostname': hostname,
                'rtt_ms': rtt,
                'geo': geo,
            })

    return {'target': target, 'hops': hops}
