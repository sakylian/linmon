#!/usr/bin/env python3
"""
route_trace.py — 路由追踪与中文位置标注

功能：
  1. 对指定 IP/域名执行 traceroute/mtr/tracepath 路由追踪
  2. 对每一跳的 IP 进行离线地理位置查询（中文标注），同时支持 IPv4 和 IPv6
  3. 标注每跳的归属地、CDN 判断、RTT 延迟
  4. 自动关联本机到目标 IP 的连接进程信息
  5. 输出 JSON 格式供 LLM 分析

灵感来源: nali (https://github.com/zu1k/nali) — 离线查询 IP 地理信息和 CDN
"""

import os
import sys
import re
import json
import shutil
import socket
import subprocess
import platform

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from geo_locator import GeoLocator, is_valid_public_ip, is_private_ip, is_ipv6

IS_WINDOWS = sys.platform == 'win32'
IS_MACOS = sys.platform == 'darwin'


def resolve_target(target):
    """将域名解析为 IP（支持 IPv4 和 IPv6）"""
    try:
        results = socket.getaddrinfo(target, None)
        for family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if family == socket.AF_INET6:
                return ip, True
            elif family == socket.AF_INET:
                return ip, False
    except socket.gaierror:
        pass
    return target, ':' in target


def run_traceroute(target, max_hops=30, timeout=5):
    """
    执行路由追踪 (跨平台: Linux/macOS/Windows)

    Args:
        target: 目标 IP 或域名
        max_hops: 最大跳数
        timeout: 每跳超时秒数

    Returns:
        dict: {target, resolved_ip, is_ipv6, hops: [{hop, ip, hostname, rtt_ms, geo}]}
    """
    # 先解析域名
    resolved_ip, is_v6 = resolve_target(target)

    # 选择工具
    cmd = None
    tool_name = None
    creationflags = 0

    if IS_WINDOWS:
        # Windows: tracert (内置)
        if shutil.which('tracert') or os.path.isfile(r'C:\Windows\System32\tracert.exe'):
            # tracert 不区分 IPv4/IPv6，自动选择
            cmd = ['tracert', '-d', '-h', str(max_hops), '-w', str(timeout * 1000), target]
            tool_name = 'tracert'
            creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    elif is_v6:
        # IPv6 路由追踪 (Linux/macOS)
        if shutil.which('traceroute'):
            cmd = ['traceroute', '-6', '-m', str(max_hops), '-w', str(timeout), '-q', '1', target]
            tool_name = 'traceroute6'
        elif shutil.which('mtr'):
            cmd = ['mtr', '-6', '--report', '--report-cycles', '1', target]
            tool_name = 'mtr6'
        elif shutil.which('tracepath'):
            cmd = ['tracepath', '-6', target]
            tool_name = 'tracepath6'
    else:
        # IPv4 路由追踪 (Linux/macOS)
        if shutil.which('traceroute'):
            cmd = ['traceroute', '-4', '-m', str(max_hops), '-w', str(timeout), '-q', '1', target]
            tool_name = 'traceroute'
        elif shutil.which('mtr'):
            cmd = ['mtr', '--report', '--report-cycles', '1', target]
            tool_name = 'mtr'
        elif shutil.which('tracepath'):
            cmd = ['tracepath', target]
            tool_name = 'tracepath'

    if not cmd:
        hints = []
        if IS_WINDOWS:
            hints.append('Windows 内置 tracert，应自动可用')
        elif IS_MACOS:
            hints.append('macOS: traceroute 已内置，或 brew install mtr')
        else:
            hints.append('Debian/Ubuntu: sudo apt install traceroute')
            hints.append('RHEL/CentOS:   sudo yum install traceroute')
            hints.append('Arch:          sudo pacman -S traceroute')
        return {
            'error': '未找到 traceroute/tracert/mtr/tracepath 命令，请安装:\n  ' + '\n  '.join(hints)
        }

    try:
        kwargs = dict(capture_output=True, text=True, timeout=max_hops * timeout + 15)
        if creationflags:
            kwargs['creationflags'] = creationflags
        result = subprocess.run(cmd, **kwargs)
        output = result.stdout or result.stderr or ''
    except subprocess.TimeoutExpired:
        return {'error': f'路由追踪超时 ({target})'}
    except FileNotFoundError:
        return {'error': f'{tool_name} 命令不可用'}
    except OSError as e:
        return {'error': f'执行 {tool_name} 失败: {e}'}

    hops = _parse_traceroute_output(output, tool_name)

    return {
        'target': target,
        'resolved_ip': resolved_ip,
        'is_ipv6': is_v6,
        'tool': tool_name,
        'hops': hops,
    }


def _parse_traceroute_output(output, tool_name):
    """解析 traceroute/mtr/tracepath/tracert 输出，提取每一跳信息"""
    hops = []
    is_tracert = tool_name == 'tracert'

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        # 跳过表头行
        if line.startswith('traceroute') or line.startswith('Too many hops') \
           or line.startswith('Resume:') or line.startswith('pmtu') \
           or line.startswith('mtr:') or line.startswith('Tracing route') \
           or line.startswith('over a maximum'):
            continue
        # tracert 结束行
        if is_tracert and (line.startswith('Trace complete') or line.startswith('command completed')):
            continue

        # 匹配跳号: tracert 格式 "  1     1 ms     1 ms     1 ms  192.168.1.1"
        #          traceroute 格式 " 1  192.168.1.1 (192.168.1.1)  0.5 ms"
        m = re.match(r'^\s*(\d+)\s+(.*)$', line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2)

        # "no reply" / "*" 跳
        if 'no reply' in rest.lower() or rest.strip() == '*' or rest.strip() == '* * *' \
           or rest.strip().startswith('* * *'):
            hops.append({
                'hop': hop_num,
                'ip': '*',
                'hostname': '',
                'rtt_ms': None,
                'geo': None,
            })
            continue

        # 提取 IP
        ip_addr = None
        # tracert -d 模式下格式为 "1 ms 1 ms 1 ms 192.168.1.1"，IP 在最后
        # 括号内 (1.2.3.4) 或 (2001:db8::1)
        ipm = re.search(r'\(([\da-fA-F:]+(?:\.\d{1,3}\.\d{1,3}\.\d{1,3})?)\)', rest)
        if not ipm:
            ipm = re.search(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', rest)
        if ipm:
            ip_addr = ipm.group(1)
        else:
            # 裸 IPv4
            bare = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', rest)
            if bare:
                ip_addr = bare.group(1)
            else:
                # 裸 IPv6
                bare6 = re.search(r'\b([\da-fA-F]{1,4}:[\da-fA-F:]+(?:\.\d{1,3}\.\d{1,3}\.\d{1,3})?)\b', rest)
                if bare6:
                    ip_addr = bare6.group(1)

        # tracert -d 模式不显示主机名（因为用了 -d），hostname 为空
        hostname = ''
        if ipm:
            # traceroute 格式: hostname (IP) -- hostname 在括号前
            before_paren = rest[:rest.index(ipm.group(0))].strip()
            # 去掉 RTT 值
            hostname = re.sub(r'\d+\.?\d*\s*ms', '', before_paren).strip()

        # RTT: 取所有 ms 值的平均（tracert 输出多个 RTT）
        rtt_values = re.findall(r'(\d+\.?\d*)\s*ms', rest)
        rtt = None
        if rtt_values:
            try:
                nums = [float(v) for v in rtt_values]
                rtt = min(nums)  # 取最低值
            except ValueError:
                rtt = None

        # 地理位置查询
        geo = None
        if ip_addr and ip_addr != '*':
            if is_private_ip(ip_addr):
                geo = {
                    'ip': ip_addr,
                    'geo_str': '局域网/内网',
                    'country': '',
                    'area': '内网',
                    'lng': None,
                    'lat': None,
                }
            elif is_valid_public_ip(ip_addr):
                geo = GeoLocator.lookup_ip(ip_addr, hostname=hostname or None)

        hops.append({
            'hop': hop_num,
            'ip': ip_addr or '*',
            'hostname': hostname,
            'rtt_ms': rtt,
            'geo': geo,
        })

    return hops


def trace_and_annotate(target, max_hops=30, timeout=5):
    """
    路由追踪 + 完整中文标注

    返回带完整地理标注的路由路径，同时标注:
    - 每跳的中文归属地
    - 跨境跳转（如果出现）
    - 延迟突变
    """
    result = run_traceroute(target, max_hops, timeout)

    if 'error' in result:
        return result

    hops = result.get('hops', [])
    annotated = []

    prev_geo = None
    for hop in hops:
        entry = {
            'hop': hop['hop'],
            'ip': hop['ip'],
            'hostname': hop.get('hostname', ''),
            'rtt_ms': hop.get('rtt_ms'),
            'geo_str': '',
            'country': '',
            'area': '',
            'lng': None,
            'lat': None,
            'cdn': None,
        }

        geo = hop.get('geo')
        if geo:
            entry['geo_str'] = geo.get('geo_str', '')
            entry['country'] = geo.get('country', '')
            entry['area'] = geo.get('area', '')
            entry['lng'] = geo.get('lng')
            entry['lat'] = geo.get('lat')
            if geo.get('cdn'):
                entry['cdn'] = geo['cdn']

        # 检测跨境跳转
        if prev_geo and entry['geo_str'] and prev_geo.get('geo_str'):
            prev_country = prev_geo.get('country', '')
            curr_country = entry.get('country', '')
            if prev_country and curr_country and prev_country != curr_country:
                entry['cross_border'] = f'{prev_country} → {curr_country}'

        annotated.append(entry)
        prev_geo = geo

    result['hops'] = annotated

    # 路径摘要
    result['path_summary'] = _build_path_summary(annotated)

    return result


def _build_path_summary(hops):
    """构建路径摘要文本"""
    if not hops:
        return '无路由信息'

    parts = []
    borders_crossed = 0
    total_rtt = 0
    rtt_count = 0

    for h in hops:
        if h['ip'] == '*':
            parts.append(f"第{h['hop']}跳: * (无响应)")
        else:
            geo = h['geo_str'] or '未知'
            rtt_str = f"{h['rtt_ms']:.1f}ms" if h['rtt_ms'] else '--'
            cdn_str = f" [{h['cdn']['provider']} CDN]" if h.get('cdn') else ''
            border_str = f"  ⚡跨境: {h['cross_border']}" if h.get('cross_border') else ''
            parts.append(f"第{h['hop']}跳: {h['ip']} [{geo}]{cdn_str} ({rtt_str}){border_str}")

        if h.get('rtt_ms'):
            total_rtt += h['rtt_ms']
            rtt_count += 1
        if h.get('cross_border'):
            borders_crossed += 1

    summary = '\n'.join(parts)
    avg_rtt = f"{total_rtt / rtt_count:.1f}ms" if rtt_count else '--'
    summary += f"\n\n总跳数: {len(hops)}  平均延迟: {avg_rtt}  跨境次数: {borders_crossed}"
    return summary


def format_trace_result(result):
    """格式化路由追踪结果为可读文本"""
    if 'error' in result:
        return f'错误: {result["error"]}'

    lines = []
    lines.append(f'路由追踪: {result["target"]} → {result.get("resolved_ip", "?")}'
                 f'  ({"IPv6" if result.get("is_ipv6") else "IPv4"}, 工具: {result.get("tool", "?")})')
    lines.append('=' * 72)

    for hop in result.get('hops', []):
        hop_num = hop['hop']
        ip = hop['ip']
        geo_str = hop.get('geo_str', '') or ''
        hostname = hop.get('hostname', '')
        rtt = hop.get('rtt_ms')
        rtt_str = f'{rtt:.1f}ms' if rtt is not None else '    --  '
        cdn_str = f' [{hop["cdn"]["provider"]} CDN]' if hop.get('cdn') else ''
        border_str = f'  ⚡跨境: {hop["cross_border"]}' if hop.get('cross_border') else ''

        if ip == '*':
            lines.append(f'  {hop_num:>2}  {"*":<42} {rtt_str}')
        else:
            ip_geo = f'{ip} [{geo_str}]{cdn_str}'
            if hostname and hostname != ip:
                ip_geo = f'{hostname} ({ip_geo})'
            lines.append(f'  {hop_num:>2}  {ip_geo:<42} {rtt_str}{border_str}')

    lines.append('=' * 72)
    lines.append(result.get('path_summary', ''))

    return '\n'.join(lines)


# ──────────────────────── CLI ────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description='路由追踪 + 中文位置标注 (IPv4/IPv6)')
    parser.add_argument('target', help='目标 IP 或域名')
    parser.add_argument('--hops', type=int, default=30, help='最大跳数 (默认 30)')
    parser.add_argument('--timeout', type=int, default=5, help='每跳超时秒数 (默认 5)')
    parser.add_argument('--json', action='store_true', help='输出 JSON 格式')
    args = parser.parse_args()

    result = trace_and_annotate(args.target, args.hops, args.timeout)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(format_trace_result(result))


if __name__ == '__main__':
    main()
