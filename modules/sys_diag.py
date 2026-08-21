#!/usr/bin/env python3
"""
sys_diag.py — 系统诊断报告模块
生成 dmesg 风格的系统诊断报告，整合进程监控和网络连接监控
"""

import os
import time
import csv
import logging
from datetime import datetime

from .proc_monitor import get_all_processes, get_system_boot_info, get_process_summary
from .net_monitor import get_all_connections, get_network_summary
from .distro_helper import get_distro
from .geo_locator import find_qqwry_dat

logger = logging.getLogger(__name__)


def generate_text_report(qqwry_path=None, include_internal=False, ai_report=None):
    """
    生成 dmesg 风格的文本报告
    """
    lines = []
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    distro = get_distro()

    lines.append('=' * 78)
    lines.append(f'  Linux 系统安全诊断报告 (linmon)')
    lines.append(f'  生成时间: {now}')
    lines.append('=' * 78)
    lines.append('')

    # ====== 第一部分: 系统信息 ======
    lines.append('[系统信息]')
    lines.append(f'  发行版: {distro.get_name()}')
    lines.append(f'  家族: {distro.get_family()} ({distro.get_id()})')
    lines.append(f'  包管理器: {distro.get_pkg_manager()}')
    lines.append(f'  服务管理器: {distro.get_service_manager()}')
    lines.append('')

    boot_info = get_system_boot_info()
    lines.append(f'  开机时间: {boot_info["boot_time_str"]}')
    lines.append(f'  运行时长: {boot_info["uptime_str"]}')
    if boot_info.get('systemd_analyze'):
        lines.append(f'  启动分析(systemd): {boot_info["systemd_analyze"]}')
    if boot_info.get('login_users'):
        lines.append(f'  当前登录用户: {", ".join(boot_info["login_users"])}')
    lines.append('')

    # ====== 第二部分: 进程监控 ======
    lines.append('-' * 78)
    lines.append('[进程监控]')
    lines.append('  正在采集进程信息...')
    processes = get_all_processes(boot_info['boot_time'])
    proc_summary = get_process_summary(processes)

    lines.append(f'  进程总数: {proc_summary["total_processes"]}')
    lines.append(f'  高危/可疑进程: {proc_summary["risky_count"]}')
    lines.append(f'  有网络连接的进程: {proc_summary["has_network"]}')
    lines.append(f'  有定时/自启配置的进程: {proc_summary["has_schedule"]}')
    lines.append(f'  监听端口总数: {proc_summary["listening_ports_count"]}')
    if proc_summary['listening_ports']:
        lines.append(f'  监听端口列表: {", ".join(str(p) for p in proc_summary["listening_ports"])}')
    lines.append('')

    # 按类别统计
    lines.append('  进程类别分布:')
    for cat, count in sorted(proc_summary['by_category'].items(), key=lambda x: -x[1]):
        lines.append(f'    {cat:20s} {count:4d}')
    lines.append('')

    # 按用户统计
    lines.append('  按用户分布:')
    for user, count in sorted(proc_summary['by_user'].items(), key=lambda x: -x[1]):
        lines.append(f'    {user:20s} {count:4d}')
    lines.append('')

    # 高危进程列表
    risky_procs = [p for p in processes if p['is_risky'] or p['risk_level'] in ('high', 'medium')]
    if risky_procs:
        lines.append(f'  [!] 高危/可疑进程 ({len(risky_procs)}个):')
        for p in risky_procs:
            lines.append(f'    [{p["risk_level"].upper()}] {p["name"]}(PID:{p["pid"]}) - {p["description"]}')
            lines.append(f'         用户: {p["username"]} | 启动: {p["start_time"]} | 路径: {p["exe"]}')
            if p['risk_reasons_str']:
                lines.append(f'         风险原因: {p["risk_reasons_str"]}')
            if p['net_conns_str'] and p['net_conns_str'] != '无活跃连接':
                lines.append(f'         网络连接: {p["net_conns_str"]}')
            if p['schedule_str'] != '无定时/自启配置':
                lines.append(f'         定时配置: {p["schedule_str"]}')
        lines.append('')
    else:
        lines.append('  [OK] 未检测到高危进程')
        lines.append('')

    # 进程启动时间线 (Top 30)
    lines.append('  进程启动时间线 (前30个):')
    for p in processes[:30]:
        delay = p['boot_delay']
        delay_marker = ''
        if delay < 0:
            delay_marker = '  [异常: 启动时间早于开机时间]'
        elif delay > 0 and delay < 30:
            delay_marker = ''
        elif delay > 300:
            delay_marker = '  [启动偏慢]'

        lines.append(
            f'    {p["start_time"]} | PID:{p["pid"]:>6} | {p["name"][:25]:<25} | '
            f'延迟:{p["boot_delay_str"]:>8} | 用户:{p["username"][:10]}{delay_marker}'
        )
    if len(processes) > 30:
        lines.append(f'    ... 共 {len(processes)} 个进程')
    lines.append('')

    # ====== 第三部分: 网络连接监控 ======
    lines.append('-' * 78)
    lines.append('[网络连接监控]')
    lines.append('  正在采集网络连接信息...')
    connections = get_all_connections(qqwry_path=qqwry_path, include_internal=include_internal)
    net_summary = get_network_summary(connections)

    lines.append(f'  连接总数: {net_summary["total_connections"]}')
    lines.append(f'  公网IP数: {net_summary["public_ip_count"]}')
    lines.append(f'  涉及国家/地区: {net_summary["country_count"]}')
    lines.append(f'  监听端口数: {net_summary["listening_ports_count"]}')
    if net_summary['listening_ports']:
        lines.append(f'  监听端口: {", ".join(str(p) for p in net_summary["listening_ports"])}')
    lines.append('')

    # 按方向统计
    lines.append('  连接方向分布:')
    for direction, count in sorted(net_summary['by_direction'].items(), key=lambda x: -x[1]):
        label = {'outbound': '传出(outbound)', 'inbound': '传入(inbound)',
                 'listen': '监听(listen)', 'unknown': '未知(unknown)'}.get(direction, direction)
        lines.append(f'    {label:30s} {count:4d}')
    lines.append('')

    # 按风险统计
    lines.append('  风险等级分布:')
    for risk, count in sorted(net_summary['by_risk'].items()):
        marker = '!!!' if risk == 'high' else ' ! ' if risk == 'medium' else '   '
        lines.append(f'    {marker} {risk:10s} {count:4d}')
    lines.append('')

    # 高危连接列表
    risky_conns = [c for c in connections if c['risk_level'] in ('high', 'medium')]
    if risky_conns:
        lines.append(f'  [!] 可疑/高危连接 ({len(risky_conns)}个):')
        for c in risky_conns[:20]:
            lines.append(
                f'    [{c["risk_level"].upper()}] {c["remote_ip"]}:{c["remote_port"]} '
                f'({c["data_type"]}) -> {c["geo"]["geo_str"]} | 进程:{c["process"]} | 方向:{c["direction"]}'
            )
            if c['risk_reasons_str']:
                lines.append(f'         原因: {c["risk_reasons_str"]}')
            if c.get('remote_os') and c['remote_os'] != '未知':
                lines.append(f'         对端OS: {c["remote_os"]}')
            if c.get('frequency_desc'):
                lines.append(f'         频率: {c["frequency_desc"]}')
        if len(risky_conns) > 20:
            lines.append(f'    ... 共 {len(risky_conns)} 个可疑连接')
        lines.append('')
    else:
        lines.append('  [OK] 未检测到高危网络连接')
        lines.append('')

    # 公网连接详情
    public_conns = [c for c in connections if c['is_public']]
    if public_conns:
        lines.append(f'  公网连接详情 ({len(public_conns)}个):')
        for c in public_conns[:30]:
            lines.append(
                f'    {c["remote_ip"]}:{c["remote_port"]:>5} | {c["data_type"]:15s} | '
                f'{c["geo"]["geo_str"]:25s} | {c["direction"]:8s} | {c["process"]:20s} | '
                f'时长:{c["age_str"]:>8} | 对端:{c["remote_os"][:30]}'
            )
        if len(public_conns) > 30:
            lines.append(f'    ... 共 {len(public_conns)} 个公网连接')
        lines.append('')

    # ====== 第四部分: 防火墙状态 ======
    lines.append('-' * 78)
    lines.append('[防火墙状态]')
    fw = distro.get_firewall_status()
    lines.append(f'  类型: {fw["type"]}')
    lines.append(f'  状态: {"启用" if fw["active"] else "未启用"}')
    if fw['rules']:
        lines.append(f'  规则数: {len(fw["rules"])}')
        for rule in fw['rules'][:10]:
            lines.append(f'    {rule}')
    lines.append('')

    # ====== 第五部分: 定时任务概览 ======
    lines.append('-' * 78)
    lines.append('[定时任务概览]')
    sched_procs = [p for p in processes if p['is_cron'] or p['is_systemd_timer'] or p['is_rc_local'] or p['is_initd']]
    if sched_procs:
        lines.append(f'  发现 {len(sched_procs)} 个进程有定时/自启配置:')
        for p in sched_procs[:20]:
            lines.append(f'    {p["name"]}(PID:{p["pid"]}) -> {p["schedule_str"]}')
    else:
        lines.append('  未发现进程关联的定时/自启配置')
    lines.append('')

    # systemctl timers
    timers = distro.get_systemd_timers()
    if timers:
        lines.append(f'  systemd 定时器 ({len(timers)} 个):')
        for t in timers[:10]:
            lines.append(f'    {t.get("unit", "")} -> 下次触发: {t.get("next", "未知")} ({t.get("activates", "")})')
    lines.append('')

    # ====== 第六部分: AI 安全分析 ======
    if ai_report:
        lines.append('-' * 78)
        lines.append('[AI 安全分析报告]')
        if ai_report.get('success'):
            lines.append(f'  分析模型: {ai_report.get("model", "未知")}')
            lines.append(f'  分析时间: {ai_report.get("timestamp", "未知")}')
            lines.append('')
            lines.append('  ' + ai_report['analysis'].replace('\n', '\n  '))
        else:
            lines.append(f'  AI分析失败: {ai_report.get("error", "未知错误")}')
        lines.append('')

    # ====== 报告结尾 ======
    lines.append('=' * 78)
    lines.append(f'  诊断完成 | 生成时间: {now} | linmon')
    lines.append('=' * 78)

    return '\n'.join(lines), {
        'processes': processes,
        'connections': connections,
        'boot_info': boot_info,
        'proc_summary': proc_summary,
        'net_summary': net_summary,
        'distro': distro.distro_info,
    }


def generate_csv_report(processes=None, connections=None, output_path='linmon_report.csv'):
    """生成 CSV 格式报告"""
    if processes is None:
        processes = get_all_processes()
    if connections is None:
        connections = get_all_connections()

    with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)

        # 进程表
        writer.writerow(['=== 进程监控 ==='])
        writer.writerow([
            'PID', '进程名', '父进程', '可执行文件', '命令行', '启动用户',
            '启动时间', '开机延迟', '运行时长', '内存', 'CPU%',
            '说明', '类别', '定时配置', '网络端口', '网络连接',
            '风险等级', '风险原因'
        ])
        for p in processes:
            writer.writerow([
                p['pid'], p['name'], p['parent_name'], p['exe'], p['cmdline'][:100],
                p['username'], p['start_time'], p['boot_delay_str'], p['uptime_str'],
                p['memory_rss_str'], p['cpu_percent'], p['description'], p['category'],
                p['schedule_str'], p['net_ports_str'], p['net_conns_str'],
                p['risk_level'], p['risk_reasons_str']
            ])

        writer.writerow([])
        writer.writerow(['=== 网络连接监控 ==='])
        writer.writerow([
            '协议', '状态', '方向', '本地地址', '远程地址',
            '数据类型', '远程IP归属地', '对端OS',
            '关联进程', '进程PID', '进程用户',
            '连接时长', '发送数据', '接收数据', '连接频率',
            '风险等级', '风险原因'
        ])
        for c in connections:
            writer.writerow([
                c['protocol'], c['state'], c['direction'],
                f'{c["local_ip"]}:{c["local_port"]}',
                f'{c["remote_ip"]}:{c["remote_port"]}',
                c['data_type'], c['geo']['geo_str'], c['remote_os'],
                c['process'], c['pid'], c['process_user'],
                c['age_str'], c['bytes_sent_str'], c['bytes_recv_str'],
                c.get('frequency_desc', ''),
                c['risk_level'], c['risk_reasons_str']
            ])

    return output_path


def generate_json_report(processes=None, connections=None, boot_info=None,
                         proc_summary=None, net_summary=None, ai_report=None):
    """生成 JSON 格式报告数据"""
    import json

    distro = get_distro()
    if processes is None:
        processes = get_all_processes()
    if connections is None:
        connections = get_all_connections()
    if boot_info is None:
        boot_info = get_system_boot_info()
    if proc_summary is None:
        proc_summary = get_process_summary(processes)
    if net_summary is None:
        net_summary = get_network_summary(connections)

    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'system': {
            'distro': distro.distro_info,
            'boot_time': boot_info['boot_time_str'],
            'uptime': boot_info['uptime_str'],
            'login_users': boot_info.get('login_users', []),
        },
        'process_summary': proc_summary,
        'network_summary': net_summary,
        'processes': processes,
        'connections': connections,
    }
    if ai_report:
        report['ai_analysis'] = ai_report

    return json.dumps(report, ensure_ascii=False, indent=2, default=str)
