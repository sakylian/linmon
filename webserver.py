#!/usr/bin/env python3
"""
webserver.py — Flask Web 服务
提供实时进程/网络监控面板 + AI分析接口
"""

import os
import sys
import json
import time
import threading
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, send_from_directory

from modules.proc_monitor import get_all_processes, get_system_boot_info, get_process_summary
from modules.net_monitor import get_all_connections, get_network_summary, run_traceroute
from modules.geo_locator import find_qqwry_dat, GeoLocator
from modules.distro_helper import get_distro
from modules.ai_analyzer import get_analyzer

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates')

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
    return render_template('index.html')


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

    return jsonify({
        'summary': summary,
        'connections': connections,
        'count': len(connections),
        'timestamp': _cached_data['timestamp'],
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


@app.route('/api/ai/test', methods=['POST'])
def api_ai_test():
    """测试AI连接"""
    analyzer = get_analyzer()
    if not analyzer.is_configured():
        return jsonify({'success': False, 'error': '未配置app_id或app_secret'}), 400
    result = analyzer._call_ai('请回复"连接成功"。')
    return jsonify(result)


def start_server(host='0.0.0.0', port=8765, debug=False):
    """启动Web服务"""
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

    print(f'  实际监听端口: {port}')
    print(f'  访问: http://localhost:{port}')
    print(f'  按 Ctrl+C 停止')
    print()

    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    start_server()
