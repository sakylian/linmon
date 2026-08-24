#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
linmon.py — Linux 进程与网络连接安全监控工具 (CLI 统一入口)
"""

import argparse
import os
import sys
import json
import logging
import time

# 添加模块路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.distro_helper import get_distro
from modules.geo_locator import find_qqwry_dat, GeoLocator
from modules.proc_monitor import get_all_processes, get_system_boot_info, get_process_summary
from modules.net_monitor import get_all_connections, get_network_summary, run_traceroute
from modules.sys_diag import generate_text_report, generate_csv_report, generate_json_report
from modules.ai_analyzer import get_analyzer
from modules.net_monitor import configure_geo_risk
from modules.audit import log_event
from modules.process_tracker import tracker

import platform as _platform

if _platform.system() == 'Windows':
    _EDITION = 'Windows Edition'
elif _platform.system() == 'Darwin':
    _EDITION = 'macOS Edition'
else:
    _EDITION = 'Linux Edition'

VERSION = f'linmon v1.0 ({_EDITION})'


def _confirm_ai_send(analyzer, processes, connections, force=False):
    """在把数据发往外部 LLM 前，显式展示将发送的内容并请求确认。
    返回 True 表示允许发送。force=True（--yes）跳过交互确认。"""
    if force:
        return True
    preview = analyzer.preview_send(processes, connections)
    if not preview['allowed']:
        print('[提示] 外部AI分析已禁用(allow_external_ai=false)，不会向任何第三方发送数据。')
        return False
    if not preview['will_send']:
        return True  # 无可疑项，generate_security_report 仅返回"安全"结论，不外发
    print('[!] 即将把以下数据外发至第三方 AI 端点进行分析:')
    print(f'    端点: {preview["endpoint"]}')
    print(f'    进程数: {preview["process_count"]}   连接数: {preview["connection_count"]}')
    print(f'    命令行脱敏: {"是" if preview["redact"] else "否(配置关闭)"}')
    print(f'    发送字段: {", ".join(preview["fields"])}')
    if not sys.stdin.isatty():
        print('[错误] 非交互环境未确认，已中止外发。可加 --yes 跳过确认。')
        return False
    ans = input('确认外发? [y/N] ').strip().lower()
    return ans in ('y', 'yes')


def check_dependencies():
    """检查依赖"""
    missing = []
    try:
        import psutil
    except ImportError:
        missing.append('psutil')
    try:
        import flask
    except ImportError:
        missing.append('flask')
    if missing:
        print(f'[警告] 缺少依赖: {", ".join(missing)}')
        print(f'请运行: pip install {" ".join(missing)}')
        return False
    return True


def cmd_boot(args):
    """显示开机信息"""
    print(f'\n{VERSION}')
    print('=' * 60)
    boot_info = get_system_boot_info()
    distro = get_distro()
    print(f'发行版: {distro.get_name()}')
    print(f'开机时间: {boot_info["boot_time_str"]}')
    print(f'运行时长: {boot_info["uptime_str"]}')
    if boot_info.get('systemd_analyze'):
        print(f'启动分析: {boot_info["systemd_analyze"]}')
    if boot_info.get('login_users'):
        print(f'当前登录用户:')
        for u in boot_info['login_users']:
            print(f'  {u}')
    print('=' * 60)


def cmd_proc(args):
    """进程监控"""
    print(f'\n{VERSION} — 进程监控')
    print('=' * 60)

    boot_info = get_system_boot_info()
    print(f'正在扫描进程...')
    processes = get_all_processes(boot_info['boot_time'],
                                   scan_schedules=not args.no_schedule,
                                   scan_network=not args.no_network)
    summary = get_process_summary(processes)

    print(f'进程总数: {summary["total_processes"]}')
    print(f'高危/可疑: {summary["risky_count"]}')
    print(f'有网络连接: {summary["has_network"]}')
    print(f'有定时配置: {summary["has_schedule"]}')
    print(f'监听端口: {summary["listening_ports_count"]}')
    if summary['listening_ports']:
        print(f'  端口列表: {", ".join(str(p) for p in summary["listening_ports"])}')
    print()

    # 显示高危进程
    if not args.all:
        risky = [p for p in processes if p['is_risky'] or p['risk_level'] in ('high', 'medium')]
        if risky:
            print(f'[!] 高危/可疑进程 ({len(risky)}个):')
            print()
            for p in risky:
                print(f'  [{p["risk_level"].upper()}] {p["name"]} (PID:{p["pid"]})')
                print(f'    用户: {p["username"]} | 启动: {p["start_time"]} | 路径: {p["exe"]}')
                print(f'    说明: {p["description"]}')
                if p['risk_reasons_str']:
                    print(f'    风险: {p["risk_reasons_str"]}')
                if p['net_conns_str'] and p['net_conns_str'] != '无活跃连接':
                    print(f'    网络: {p["net_conns_str"]}')
                if p['schedule_str'] != '无定时/自启配置':
                    print(f'    定时: {p["schedule_str"]}')
                print()
        else:
            print('[OK] 未检测到高危进程')
    else:
        print(f'进程启动时间线 ({len(processes)}个):')
        print()
        for p in processes:
            print(f'  {p["start_time"]} | PID:{p["pid"]:>6} | {p["name"][:25]:<25} | '
                  f'用户:{p["username"][:10]:<10} | 延迟:{p["boot_delay_str"]:>8}'
                  f'{" [!]" if p["is_risky"] else ""}')

    # AI 分析
    if args.ai:
        analyzer = get_analyzer()
        if not analyzer.is_enabled():
            print('[提示] AI分析未启用, 请先配置: linmon ai-config --set app_key=你的AppKey --enable')
        elif not _confirm_ai_send(analyzer, processes, [], args.yes):
            print('[AI] 已取消外发')
        else:
            print('[AI] 正在分析高危进程...')
            risky = [p for p in processes if p['is_risky'] or p['risk_level'] in ('high', 'medium')]
            if risky:
                result = analyzer.generate_security_report(processes, [])
                if result.get('success'):
                    print(f'\n[AI分析结果]\n{result["analysis"]}')
                else:
                    print(f'[AI] 分析失败: {result.get("error")}')
            else:
                print('[AI] 无高危进程需要分析')

    if args.output:
        import csv
        with open(args.output, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.writer(f)
            w.writerow(['PID', '进程名', '启动用户', '启动时间', '路径', '网络连接', '定时配置', '风险等级', '风险原因'])
            for p in processes:
                w.writerow([p['pid'], p['name'], p['username'], p['start_time'],
                            p['exe'], p['net_conns_str'], p['schedule_str'],
                            p['risk_level'], p['risk_reasons_str']])
        print(f'\n已保存CSV: {args.output}')


def cmd_net(args):
    """网络连接监控"""
    print(f'\n{VERSION} — 网络连接监控')
    print('=' * 60)

    qqwry = find_qqwry_dat()
    if qqwry:
        print(f'IP库: {qqwry}')
    else:
        print('[提示] 未找到qqwry.dat, IP归属地查询不可用')

    print(f'正在扫描网络连接...')
    connections = get_all_connections(qqwry_path=qqwry, include_internal=args.all,
                                      detect_os=args.os)
    summary = get_network_summary(connections)

    print(f'连接总数: {summary["total_connections"]}')
    print(f'公网IP数: {summary["public_ip_count"]}')
    print(f'涉及国家: {summary["country_count"]}')
    print()

    print('风险等级分布:')
    for risk in ('high', 'medium', 'low'):
        count = summary['by_risk'].get(risk, 0)
        marker = '!!!' if risk == 'high' else ' ! ' if risk == 'medium' else '   '
        print(f'  {marker} {risk:10s} {count:4d}')
    print()

    if args.all:
        print('所有连接:')
    else:
        print('公网连接:')
    print()

    for c in connections:
        if not args.all and not c['is_public']:
            continue
        risk_marker = '!' if c['risk_level'] == 'high' else '*' if c['risk_level'] == 'medium' else ' '
        # LISTEN 状态显示本地地址，其他显示远程地址
        if c['direction'] == 'listen' or (c['remote_port'] == 0 and c['remote_ip'] in ('0.0.0.0', '::')):
            addr_str = f'{c["local_ip"]}:{c["local_port"]:>5}'
            geo_str = ''
        else:
            addr_str = f'{c["local_ip"]}:{c["local_port"]:>5} -> {c["remote_ip"]}:{c["remote_port"]:>5}'
            geo_str = c['geo']['geo_str']
        proc_str = c['process'][:20] if c['process'] else f'PID:{c["pid"]}' if c['pid'] else ''
        print(f'  [{risk_marker}] {c["protocol"]:4s} {c["state"]:10s} {addr_str} '
              f'({c["data_type"]:15s}) {geo_str:25s} | {c["direction"]:8s} | {proc_str}')
        if c['risk_reasons_str']:
            print(f'      风险: {c["risk_reasons_str"]}')
        if c.get('remote_os') and c['remote_os'] != '未知' and c.get('remote_os') != '未知(不可达或ICMP被过滤)':
            print(f'      对端OS: {c["remote_os"]}')
        if c.get('frequency_desc') and '无采样' not in c.get('frequency_desc', ''):
            print(f'      频率: {c["frequency_desc"]}')

    # AI 分析
    if args.ai:
        analyzer = get_analyzer()
        if not analyzer.is_enabled():
            print('[提示] AI分析未启用, 请先配置: linmon ai-config --set app_key=你的AppKey --enable')
        elif not _confirm_ai_send(analyzer, [], connections, args.yes):
            print('[AI] 已取消外发')
        else:
            print('[AI] 正在分析可疑连接...')
            risky = [c for c in connections if c['risk_level'] in ('high', 'medium')]
            if risky:
                result = analyzer.generate_security_report([], risky)
                if result.get('success'):
                    print(f'\n[AI分析结果]\n{result["analysis"]}')
                else:
                    print(f'[AI] 分析失败: {result.get("error")}')
            else:
                print('[AI] 无可疑连接需要分析')

    if args.output:
        import csv
        with open(args.output, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.writer(f)
            w.writerow(['协议', '状态', '方向', '本地', '远程', '数据类型', '归属地',
                        '对端OS', '进程', 'PID', '时长', '风险', '原因'])
            for c in connections:
                w.writerow([c['protocol'], c['state'], c['direction'],
                            f'{c["local_ip"]}:{c["local_port"]}',
                            f'{c["remote_ip"]}:{c["remote_port"]}',
                            c['data_type'], c['geo']['geo_str'], c['remote_os'],
                            c['process'], c['pid'], c['age_str'],
                            c['risk_level'], c['risk_reasons_str']])
        print(f'\n已保存CSV: {args.output}')


def cmd_track(args):
    """在限定时间内采样跟踪一个可疑进程。"""
    try:
        session = tracker.start(args.pid, duration=args.duration, interval=args.interval)
    except Exception as exc:
        print(f'[错误] 无法启动跟踪: {exc}')
        return
    print(f"正在跟踪 {session['process_name']} (PID {session['pid']})，任务 {session['id']} ...")
    while True:
        current = tracker.get(session['id'])
        if current['status'] != 'running':
            break
        time.sleep(min(1.0, args.interval))
    report = tracker.report(session['id'])
    print(f"\n{report['summary']}")
    for item in report['concerns']:
        print(f'  - {item}')
    print('建议：')
    for item in report['recommended_actions']:
        print(f'  - {item}')
    if args.ai:
        analyzer = get_analyzer()
        if not analyzer.is_enabled():
            print('[AI] AI分析未启用')
        elif not args.yes and (not sys.stdin.isatty() or input('确认把最小化跟踪摘要发送给外部AI? [y/N] ').strip().lower() not in ('y', 'yes')):
            print('[AI] 已取消外发')
        else:
            result = analyzer.analyze_tracking_report(report)
            print(f"\n[AI跟踪报告]\n{result.get('analysis') or result.get('error')}")


def cmd_diag(args):
    """系统全面诊断"""
    qqwry = find_qqwry_dat()
    ai_report = None

    if args.ai:
        analyzer = get_analyzer()
        if not analyzer.is_enabled():
            print('[提示] AI分析未启用, 请配置config/ai_config.json')
        else:
            processes = get_all_processes()
            connections = get_all_connections(qqwry_path=qqwry)
            if _confirm_ai_send(analyzer, processes, connections, args.yes):
                print('[AI] 正在进行AI安全分析...')
                ai_report = analyzer.generate_security_report(processes, connections)
            else:
                print('[AI] 已取消外发')

    report, data = generate_text_report(qqwry_path=qqwry, ai_report=ai_report)
    print(report)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        log_event('report_export', f'format=text path={args.output}')
        print(f'\n已保存报告: {args.output}')

    if args.csv:
        generate_csv_report(data['processes'], data['connections'], args.csv)
        log_event('report_export', f'format=csv path={args.csv}')
        print(f'已保存CSV: {args.csv}')

    if args.json:
        json_data = generate_json_report(
            data['processes'], data['connections'], data['boot_info'],
            data['proc_summary'], data['net_summary'], ai_report
        )
        with open(args.json, 'w', encoding='utf-8') as f:
            f.write(json_data)
        log_event('report_export', f'format=json path={args.json}')
        print(f'已保存JSON: {args.json}')


def cmd_trace(args):
    """路由跟踪"""
    print(f'\n{VERSION} — 路由跟踪: {args.target}')
    print('=' * 60)

    result = run_traceroute(args.target, max_hops=args.hops, timeout=args.timeout)

    if 'error' in result:
        print(f'错误: {result["error"]}')
        return

    print(f'目标: {result["target"]}')
    print()
    for hop in result['hops']:
        ip = hop.get('ip', '*')
        rtt = hop.get('rtt_ms')
        rtt_str = f'{rtt:.1f}ms' if rtt else '*'
        geo = hop.get('geo', {})
        geo_str = geo.get('geo_str', '') if geo else ''
        print(f'  {hop["hop"]:>2}  {ip:<18} {rtt_str:>8}  {geo_str}')

    if args.ai:
        analyzer = get_analyzer()
        if analyzer.is_enabled():
            print('\n[AI] 正在分析路由...')
            hops_text = '\n'.join([f'{h["hop"]}. {h.get("ip","*")} ({h.get("geo",{}).get("geo_str","")})' for h in result['hops']])
            r = analyzer._call_ai(
                f'请分析以下到{args.target}的路由路径是否存在安全隐患:\n\n{hops_text}',
                '你是网络安全分析师,请分析路由路径是否经过可疑节点。'
            )
            if r['success']:
                print(f'\n{r["analysis"]}')


def cmd_update(args):
    """更新 IP/地理/CDN 数据库 (参考 nali 的更新逻辑)"""
    from modules.db_updater import update_databases, VALID_DB

    db_list = None
    if getattr(args, 'db', None):
        db_list = [d.strip().lower() for d in args.db.split(',') if d.strip()]
        invalid = [d for d in db_list if d not in VALID_DB]
        if invalid:
            print(f'无效的数据库: {", ".join(invalid)}')
            print(f'可选: {", ".join(sorted(VALID_DB))}')
            sys.exit(1)

    print(f'\n{VERSION} — 数据库更新')
    print('=' * 60)
    if db_list:
        print(f'仅更新: {", ".join(db_list)}')
    else:
        print(f'更新全部: {", ".join(sorted(VALID_DB))}')

    ok = update_databases(db_list)
    print('=' * 60)
    if ok:
        print('数据库更新完成。下次 geo 研判将使用新库。')
    else:
        print('部分数据库更新失败，请检查网络后重试。')
        sys.exit(1)


def cmd_web(args):
    """启动Web服务"""
    from webserver import start_server
    start_server(host=args.host, port=args.port, debug=args.debug)


def cmd_ai_config(args):
    """AI配置"""
    analyzer = get_analyzer()
    cfg = analyzer.config

    if args.show:
        print(json.dumps({k: ('***' + v[-4:] if v and k in ('app_key', 'app_secret') else v) for k, v in cfg.items()},
                         ensure_ascii=False, indent=2))
    elif args.set:
        for kv in args.set:
            if '=' in kv:
                key, val = kv.split('=', 1)
                cfg[key] = val
                print(f'设置 {key} = {val if key not in ("app_key", "app_secret") else "***"}')
        path = analyzer.save_config(cfg)
        print(f'已保存配置: {path}')
    elif args.enable:
        cfg['enabled'] = True
        path = analyzer.save_config(cfg)
        print(f'AI分析已启用, 配置: {path}')
    elif args.disable:
        cfg['enabled'] = False
        path = analyzer.save_config(cfg)
        print(f'AI分析已禁用, 配置: {path}')
    elif args.test:
        if not analyzer.is_configured():
            print('[错误] 请先配置 app_key')
            return
        print('[测试] 正在连接星辰AI端点...')
        r = analyzer._call_ai('请回复"连接成功"四个字。')
        if r['success']:
            print(f'[成功] AI连接正常')
            print(f'回复: {r["analysis"][:200]}')
        else:
            print(f'[失败] {r["error"]}')

    if not any([args.show, args.set, args.enable, args.disable, args.test]):
        print('AI配置文件路径:')
        for p in [os.path.join(os.path.dirname(__file__), 'config', 'ai_config.json'),
                  os.path.expanduser('~/.config/linmon/ai_config.json'), '/etc/linmon/ai_config.json']:
            print(f'  {p}')
        print()
        print(json.dumps({k: ('***' + v[-4:] if v and k in ('app_key', 'app_secret') else v) for k, v in cfg.items()},
                         ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(
        prog='linmon',
        description=f'{VERSION} — 进程与网络连接安全监控工具',
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # boot
    p_boot = subparsers.add_parser('boot', help='显示开机信息')

    # proc
    p_proc = subparsers.add_parser('proc', help='进程监控')
    p_proc.add_argument('--all', action='store_true', help='显示所有进程(不只高危)')
    p_proc.add_argument('--no-network', action='store_true', help='跳过网络扫描')
    p_proc.add_argument('--no-schedule', action='store_true', help='跳过定时任务扫描')
    p_proc.add_argument('--ai', action='store_true', help='启用AI安全分析')
    p_proc.add_argument('--yes', action='store_true', help='跳过AI外发确认(非交互/自动化使用)')
    p_proc.add_argument('-o', '--output', help='保存CSV到指定路径')

    # net
    p_net = subparsers.add_parser('net', help='网络连接监控')
    p_net.add_argument('--all', action='store_true', help='包含内部连接')
    p_net.add_argument('--os', action='store_true', help='探测对端操作系统(TTL指纹,较慢)')
    p_net.add_argument('--ai', action='store_true', help='启用AI安全分析')
    p_net.add_argument('--yes', action='store_true', help='跳过AI外发确认(非交互/自动化使用)')
    p_net.add_argument('-o', '--output', help='保存CSV到指定路径')

    # diag
    p_diag = subparsers.add_parser('diag', help='系统全面诊断')
    p_diag.add_argument('--ai', action='store_true', help='启用AI安全分析')
    p_diag.add_argument('--yes', action='store_true', help='跳过AI外发确认(非交互/自动化使用)')
    p_diag.add_argument('-o', '--output', help='保存文本报告')
    p_diag.add_argument('--csv', help='保存CSV报告')
    p_diag.add_argument('--json', help='保存JSON报告')

    # trace
    p_trace = subparsers.add_parser('trace', help='路由跟踪')
    p_trace.add_argument('target', help='目标IP/域名')
    p_trace.add_argument('--hops', type=int, default=30, help='最大跳数(默认30)')
    p_trace.add_argument('--timeout', type=int, default=5, help='超时秒数(默认5)')
    p_trace.add_argument('--ai', action='store_true', help='AI分析路由安全')

    # track
    p_track = subparsers.add_parser('track', help='跟踪可疑进程的文件与网络活动')
    p_track.add_argument('pid', type=int, help='要跟踪的进程 PID')
    p_track.add_argument('--duration', type=int, default=60, help='跟踪秒数(5-3600，默认60)')
    p_track.add_argument('--interval', type=float, default=2, help='采样间隔秒数(默认2)')
    p_track.add_argument('--ai', action='store_true', help='用AI整理跟踪简报')
    p_track.add_argument('--yes', action='store_true', help='跳过AI外发确认')

    # web
    p_web = subparsers.add_parser('web', help='启动Web监控服务')
    p_web.add_argument('--host', default=None, help='监听地址(默认读取 web_config.json，未配置则 127.0.0.1)')
    p_web.add_argument('--port', type=int, default=None, help='监听端口(默认读取 web_config.json，未配置则 8765)')
    p_web.add_argument('--debug', action='store_true', help='调试模式')

    # update
    p_update = subparsers.add_parser('update', help='更新 IP/地理/CDN 数据库')
    p_update.add_argument('--db', default=None,
                          help='仅更新指定数据库，逗号分隔: qqwry,cdn,zxipv6wry (默认全部)')

    # ai-config
    p_ai = subparsers.add_parser('ai-config', help='AI配置管理')
    p_ai.add_argument('--show', action='store_true', help='显示当前配置')
    p_ai.add_argument('--set', nargs='+', metavar='KEY=VALUE', help='设置配置项')
    p_ai.add_argument('--enable', action='store_true', help='启用AI分析')
    p_ai.add_argument('--disable', action='store_true', help='禁用AI分析')
    p_ai.add_argument('--test', action='store_true', help='测试AI连接')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # 将 AI 配置中的地理高风险规则注入网络监控（仅本地规则，默认关闭）
    try:
        _a = get_analyzer()
        configure_geo_risk(_a.config.get('geo_risk_enabled', False),
                           _a.config.get('high_risk_regions', []))
    except Exception:
        pass

    if not check_dependencies():
        sys.exit(1)

    {
        'boot': cmd_boot,
        'proc': cmd_proc,
        'net': cmd_net,
        'diag': cmd_diag,
        'trace': cmd_trace,
        'track': cmd_track,
        'web': cmd_web,
        'update': cmd_update,
        'ai-config': cmd_ai_config,
    }[args.command](args)


if __name__ == '__main__':
    main()
