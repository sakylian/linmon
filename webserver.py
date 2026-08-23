#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
webserver.py — Flask Web 服务
提供实时进程/网络监控面板 + AI分析接口
"""

import os
import sys
import json
import time
import re
import secrets
import subprocess
import threading
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, send_from_directory, Response

from modules.proc_monitor import get_all_processes, get_system_boot_info, get_process_summary
from modules.net_monitor import get_all_connections, get_network_summary, run_traceroute, capture_traffic, start_frequency_sampler, configure_geo_risk
from modules.geo_locator import find_qqwry_dat, GeoLocator, is_valid_public_ip
from modules.distro_helper import get_distro
from modules.ai_analyzer import get_analyzer
from modules.audit import log_event

# 是否运行在 macOS (Darwin)
IS_MACOS = sys.platform == 'darwin'

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates')

# ===================== Web 面板配置与鉴权 =====================
WEB_CONFIG_PATHS = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'web_config.json'),
    os.path.expanduser('~/.config/linmon/web_config.json'),
    '/etc/linmon/web_config.json',
]
DEFAULT_WEB_CONFIG = {
    'host': '127.0.0.1',     # 默认仅本机，避免把监控面板暴露到全网
    'port': 8765,
    'auth_enabled': True,     # 默认开启令牌鉴权
    'auth_token': '',         # 为空时启动时自动生成并写回
    'home_coord': [104.0, 35.0],  # 本机(连线源点)坐标 [经度, 纬度]，可改为服务器实际所在地
}


def _load_web_config():
    cfg = DEFAULT_WEB_CONFIG.copy()
    for p in WEB_CONFIG_PATHS:
        if p and os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    cfg.update(json.load(f))
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f'加载 web 配置失败 {p}: {e}')
            break
    # 自动生成令牌并持久化
    if cfg.get('auth_enabled') and not cfg.get('auth_token'):
        cfg['auth_token'] = secrets.token_hex(16)
        _save_web_config(cfg)
    return cfg


def _save_web_config(cfg):
    path = WEB_CONFIG_PATHS[0]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=4)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# 全局 web 配置（启动后填充）
_web_cfg = None

# 本机(连线源点)坐标缓存：优先用配置的 home_coord，否则尝试本地探测出口公网IP并查本地 geo
_HOME_COORD_CACHE = None


def _get_home_coordinate(cfg):
    """确定本机(地图连线源点)坐标。

    策略：
      1. 优先使用配置 home_coord；
      2. 若本机存在出口公网IP，则用本地 GeoLocator 查询其坐标（纯本地查询，不外发任何数据）；
      3. 探测失败则回退到配置值。
    """
    configured = cfg.get('home_coord') or [104.0, 35.0]
    try:
        # macOS 用 route get 探测出口 IP（无 ip 命令）；Linux 用 ip route get
        if IS_MACOS:
            out = subprocess.run(['route', '-n', 'get', '1.1.1.1'],
                                 capture_output=True, text=True, timeout=3)
            m = re.search(r'interface:\s*\S+\s*\n\s*gateway:\s+(\d{1,3}(?:\.\d{1,3}){3})', out.stdout)
            # 也可能直接拿不到公网IP，走默认配置
            pub = None
            if m:
                pub = m.group(1)
            else:
                m2 = re.search(r'source:\s+(\d{1,3}(?:\.\d{1,3}){3})', out.stdout)
                if m2:
                    pub = m2.group(1)
            if pub and is_valid_public_ip(pub):
                g = GeoLocator.lookup_ip(pub)
                if g.get('lng') is not None and g.get('lat') is not None:
                    return [g['lng'], g['lat']], g.get('geo_str') or '本机'
        else:
            out = subprocess.run(['ip', 'route', 'get', '1.1.1.1'],
                                 capture_output=True, text=True, timeout=3)
            m = re.search(r'src\s+(\d{1,3}(?:\.\d{1,3}){3})', out.stdout)
            if m and is_valid_public_ip(m.group(1)):
                g = GeoLocator.lookup_ip(m.group(1))
                if g.get('lng') is not None and g.get('lat') is not None:
                    return [g['lng'], g['lat']], g.get('geo_str') or '本机'
    except Exception:
        logger.debug('探测本机出口IP坐标失败，回退到配置坐标', exc_info=True)
    return configured, '本机'


def _current_token():
    # 允许通过环境变量临时覆盖（便于脚本/自动化）
    return os.environ.get('LINMON_WEB_TOKEN') or (_web_cfg or {}).get('auth_token', '')


@app.before_request
def _auth_guard():
    """保护所有 /api/* 接口；未携带有效 Bearer 令牌即 401。"""
    cfg = _web_cfg or DEFAULT_WEB_CONFIG
    if not cfg.get('auth_enabled'):
        return
    if not request.path.startswith('/api/'):
        return
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[7:].strip()
    else:
        token = request.args.get('token', '')
    expected = _current_token()
    if not expected or not token or not secrets.compare_digest(token, expected):
        return jsonify({'error': '未授权: 缺少或错误的访问令牌'}), 401


# 静态资源路由 (echarts.min.js, world.json 等)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


@app.route('/data/<path:filename>')
def serve_data(filename):
    return send_from_directory(DATA_DIR, filename)


# 数据缓存
_data_lock = threading.Lock()
_cached_data = {
    'processes': None,
    'connections': None,
    'boot_info': None,
    'proc_summary': None,
    'net_summary': None,
    'timestamp': 0,
}
_cache_ttl = 5  # 缓存有效期5秒


def _refresh_data(force=False):
    """刷新缓存数据"""
    with _data_lock:
        now = time.time()
        if not force and now - _cached_data['timestamp'] < _cache_ttl:
            return

        qqwry = find_qqwry_dat()
        boot_info = get_system_boot_info()
        processes = get_all_processes(boot_info['boot_time'])
        connections = get_all_connections(qqwry_path=qqwry)
        proc_summary = get_process_summary(processes)
        net_summary = get_network_summary(connections)

        _cached_data.update({
            'processes': processes,
            'connections': connections,
            'boot_info': boot_info,
            'proc_summary': proc_summary,
            'net_summary': net_summary,
            'timestamp': now,
        })


@app.route('/')
def index():
    edition = 'macOS' if IS_MACOS else 'Linux'
    return render_template('index.html', edition=edition)


@app.route('/api/sysinfo')
def api_sysinfo():
    """系统信息"""
    _refresh_data()
    boot_info = _cached_data['boot_info']
    distro = get_distro()
    return jsonify({
        'distro': distro.distro_info,
        'boot_time': boot_info['boot_time_str'],
        'uptime': boot_info['uptime_str'],
        'login_users': boot_info.get('login_users', []),
        'server_time': time.strftime('%Y-%m-%d %H:%M:%S'),
    })


@app.route('/api/processes')
def api_processes():
    """进程列表"""
    force = request.args.get('refresh', '0') == '1'
    _refresh_data(force=force)
    processes = _cached_data['processes']
    summary = _cached_data['proc_summary']

    # 可选筛选
    risky_only = request.args.get('risky') == '1'
    if risky_only:
        processes = [p for p in processes if p['is_risky'] or p['risk_level'] in ('high', 'medium')]

    return jsonify({
        'summary': summary,
        'processes': processes,
        'count': len(processes),
        'timestamp': _cached_data['timestamp'],
    })


@app.route('/api/connections')
def api_connections():
    """网络连接列表"""
    force = request.args.get('refresh', '0') == '1'
    _refresh_data(force=force)
    connections = _cached_data['connections']
    summary = _cached_data['net_summary']

    # 可选筛选
    public_only = request.args.get('public') == '1'
    if public_only:
        connections = [c for c in connections if c['is_public']]

    risky_only = request.args.get('risky') == '1'
    if risky_only:
        connections = [c for c in connections if c['risk_level'] in ('high', 'medium')]

    global _HOME_COORD_CACHE
    if _HOME_COORD_CACHE is None:
        _HOME_COORD_CACHE = _get_home_coordinate(_web_cfg or DEFAULT_WEB_CONFIG)
    home_coord, home_geo_str = _HOME_COORD_CACHE

    return jsonify({
        'summary': summary,
        'connections': connections,
        'count': len(connections),
        'timestamp': _cached_data['timestamp'],
        'home_coord': home_coord,
        'home_geo_str': home_geo_str,
    })


@app.route('/api/overview')
def api_overview():
    """综合概览"""
    _refresh_data()
    return jsonify({
        'system': {
            **_cached_data['boot_info'],
            'distro': get_distro().distro_info,
        },
        'proc_summary': _cached_data['proc_summary'],
        'net_summary': _cached_data['net_summary'],
        'timestamp': _cached_data['timestamp'],
        'server_time': time.strftime('%Y-%m-%d %H:%M:%S'),
    })


@app.route('/api/traceroute', methods=['POST'])
def api_traceroute():
    """路由跟踪"""
    data = request.get_json() or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': '请提供target参数'}), 400

    max_hops = int(data.get('hops', 30))
    timeout = int(data.get('timeout', 5))

    result = run_traceroute(target, max_hops=max_hops, timeout=timeout)
    return jsonify(result)


@app.route('/api/capture', methods=['POST'])
def api_capture():
    """对指定远端连接抓包并做本地分析（不对外发送数据）"""
    data = request.get_json() or {}
    remote_ip = (data.get('remote_ip') or '').strip()
    if not remote_ip:
        return jsonify({'error': '请提供 remote_ip 参数'}), 400
    remote_port = int(data.get('remote_port') or 0)
    count = int(data.get('count') or 60)
    timeout = int(data.get('timeout') or 8)
    result = capture_traffic(
        remote_ip,
        remote_port if remote_port else None,
        count=count,
        timeout=timeout,
    )
    return jsonify(result)


@app.route('/api/ai/config', methods=['GET', 'POST'])
def api_ai_config():
    """AI配置管理"""
    analyzer = get_analyzer()

    if request.method == 'GET':
        cfg = analyzer.config.copy()
        if cfg.get('app_secret'):
            cfg['app_secret'] = '***' + cfg['app_secret'][-4:]
        if cfg.get('app_id'):
            cfg['app_id'] = cfg['app_id'][:4] + '****'
        return jsonify(cfg)

    elif request.method == 'POST':
        data = request.get_json() or {}
        for key in ('endpoint', 'model_name', 'model_id', 'app_id', 'app_secret',
                     'tokenhub_url', 'enabled', 'max_tokens', 'temperature'):
            if key in data:
                old_val = analyzer.config.get(key)
                new_val = data[key]
                # 不覆盖已有的 secret（除非显式传入）
                if key in ('app_id', 'app_secret') and new_val and new_val.startswith('***'):
                    continue
                analyzer.config[key] = new_val
        path = analyzer.save_config()
        log_event('config_change', f'ai_config saved (enabled={analyzer.is_enabled()}, allow_external_ai={analyzer.is_external_allowed()})')
        return jsonify({'success': True, 'path': path, 'enabled': analyzer.is_enabled()})


@app.route('/api/ai/analyze', methods=['POST'])
def api_ai_analyze():
    """AI分析"""
    analyzer = get_analyzer()
    if not analyzer.is_enabled():
        return jsonify({
            'success': False,
            'error': 'AI分析未启用，请在配置中设置app_id/app_secret并启用(POST /api/ai/config)'
        }), 400

    data = request.get_json() or {}
    target_type = data.get('type', 'auto')  # process / connection / overview

    if target_type == 'overview' or not data.get('target'):
        # 综合安全报告
        _refresh_data(force=True)
        result = analyzer.generate_security_report(
            _cached_data['processes'], _cached_data['connections']
        )
        return jsonify(result)

    elif target_type == 'process':
        pid = int(data.get('pid', 0))
        if not pid:
            return jsonify({'error': '请提供pid参数'}), 400
        _refresh_data()
        proc = next((p for p in _cached_data['processes'] if p['pid'] == pid), None)
        if not proc:
            return jsonify({'error': f'未找到PID {pid}'}), 404
        result = analyzer.analyze_process(proc)
        return jsonify(result)

    elif target_type == 'connection':
        remote_ip = data.get('remote_ip', '')
        remote_port = int(data.get('remote_port', 0))
        _refresh_data()
        conn = next((c for c in _cached_data['connections']
                     if c['remote_ip'] == remote_ip and c['remote_port'] == remote_port), None)
        if not conn:
            return jsonify({'error': f'未找到连接 {remote_ip}:{remote_port}'}), 404
        result = analyzer.analyze_connection(conn)
        return jsonify(result)

    return jsonify({'error': '不支持的type参数'}), 400


@app.route('/api/ai/preview', methods=['POST'])
def api_ai_preview():
    """返回即将发往外部 LLM 的数据摘要（用于发送前确认，不发起外发）"""
    analyzer = get_analyzer()
    if not analyzer.is_enabled():
        return jsonify({'enabled': False})
    _refresh_data(force=True)
    preview = analyzer.preview_send(_cached_data['processes'], _cached_data['connections'])
    preview['enabled'] = True
    preview['endpoint'] = analyzer.config.get('endpoint', '')
    return jsonify(preview)


@app.route('/api/ai/test', methods=['POST'])
def api_ai_test():
    """测试AI连接"""
    analyzer = get_analyzer()
    if not analyzer.is_configured():
        return jsonify({'success': False, 'error': '未配置app_id或app_secret'}), 400
    if not analyzer.is_external_allowed():
        return jsonify({'success': False, 'error': '外部AI分析已禁用(allow_external_ai=false)，不会向任何第三方发送数据。'}), 400
    result = analyzer._call_ai('请回复"连接成功"。')
    return jsonify(result)


def _safe_filename(ts):
    """把时间戳转为安全文件名片段"""
    s = re.sub(r'[^\w\-]+', '_', ts or '')
    return s[:40] or 'report'


@app.route('/api/ai/export', methods=['POST'])
def api_ai_export():
    """导出 AI 安全分析报告为 Markdown 或 PDF"""
    data = request.get_json() or {}
    fmt = (data.get('format') or 'md').lower()
    report = {
        'title': data.get('title') or 'AI 安全分析报告',
        'timestamp': data.get('timestamp') or time.strftime('%Y-%m-%d %H:%M:%S'),
        'target_type': data.get('target_type') or 'overview',
        'target': data.get('target') or '',
        'analysis': data.get('analysis') or '',
    }
    fname = 'ai_report_%s' % _safe_filename(report['timestamp'])

    if fmt == 'md':
        from modules.report_exporter import export_markdown
        content = export_markdown(report)
        return Response(content, mimetype='text/markdown',
                         headers={'Content-Disposition': 'attachment; filename="%s.md"' % fname})

    if fmt == 'pdf':
        from modules.report_exporter import export_pdf
        try:
            pdf_bytes = export_pdf(report)
        except Exception as e:  # 例如 reportlab 未安装
            logger.exception('PDF 导出失败')
            return jsonify({'error': 'PDF 生成失败: %s' % e}), 500
        return Response(pdf_bytes, mimetype='application/pdf',
                        headers={'Content-Disposition': 'attachment; filename="%s.pdf"' % fname})

    return jsonify({'error': '不支持的格式: %s (支持 md / pdf)' % fmt}), 400


def start_server(host=None, port=None, debug=False):
    """启动Web服务。host/port 为 None 时读取 web_config.json（默认 127.0.0.1:8765）。"""
    global _web_cfg
    _web_cfg = _load_web_config()
    host = host or _web_cfg.get('host') or '127.0.0.1'
    port = port or _web_cfg.get('port') or 8765
    try:
        _a = get_analyzer()
        configure_geo_risk(_a.config.get('geo_risk_enabled', False),
                           _a.config.get('high_risk_regions', []))
        log_event('web_start', f'host={host} port={port} auth={_web_cfg.get("auth_enabled")}')
    except Exception:
        pass
    try:
        start_frequency_sampler(interval=30)
    except Exception:
        pass

    print(f'''
╔════════════════════════════════════════════════════╗
║  linmon Web 监控服务                               ║
║  监听: http://{host}:{port:<24}║
║  功能: 进程监控 | 网络连接 | AI分析 | 路由跟踪     ║
╚════════════════════════════════════════════════════╝
''')

    # 自动寻找可用端口
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while True:
        try:
            sock.bind((host, port))
            break
        except socket.error:
            port += 1
            if port > 9999:
                print('[错误] 无法找到可用端口')
                return
    sock.close()

    token = _current_token()
    print(f'  实际监听端口: {port}')
    print(f'  访问: http://localhost:{port}')
    if _web_cfg.get('auth_enabled'):
        print(f'  访问令牌: {token}')
        print(f'  登录方式: http://localhost:{port}/?token={token}')
        print(f'  令牌已保存至 config/web_config.json（权限 0600）')
    print(f'  按 Ctrl+C 停止')
    print()

    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    start_server()
