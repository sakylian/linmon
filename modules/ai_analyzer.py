#!/usr/bin/env python3
"""
ai_analyzer.py — 天翼云AI智能分析模块
通过天翼云 TokenHub 认证，调用AI端点对高危进程和可疑网络连接进行智能分析
"""

import os
import json
import time
import logging
import urllib.request
import urllib.error
from pathlib import Path

logger = logging.getLogger(__name__)

# 配置文件路径
CONFIG_PATHS = [
    os.path.join(os.path.dirname(__file__), '..', 'config', 'ai_config.json'),
    os.path.expanduser('~/.config/linmon/ai_config.json'),
    '/etc/linmon/ai_config.json',
]

# 默认配置
DEFAULT_CONFIG = {
    'endpoint': 'https://ai.ctaigw.cn/v1/chat/completions',
    'model_name': 'glm-5.3',
    'model_id': 'e8e2511658054053a7e56e950d80f0e4',
    'app_id': '',
    'app_key': '',
    'max_tokens': 8192,
    'temperature': 0.3,
    'timeout': 60,
    'enabled': False,
    'auto_analyze_risky': True,
}


class AIAnalyzer:
    """天翼云AI分析器"""

    def __init__(self, config_path=None):
        self.config = self._load_config(config_path)
        self._token = None
        self._token_expire = 0

    def _load_config(self, config_path=None):
        """加载AI配置"""
        paths = [config_path] if config_path else CONFIG_PATHS
        for p in paths:
            if p and os.path.isfile(p):
                try:
                    with open(p, 'r', encoding='utf-8') as f:
                        cfg = json.load(f)
                    # 合并默认配置
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(cfg)
                    return merged
                except (json.JSONDecodeError, IOError) as e:
                    logger.warning(f'加载AI配置失败 {p}: {e}')
        return DEFAULT_CONFIG.copy()

    def save_config(self, config=None, path=None):
        """保存配置到文件"""
        if config:
            self.config.update(config)
        save_path = path or CONFIG_PATHS[0]
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, ensure_ascii=False, indent=4)
        return save_path

    def is_configured(self):
        """检查是否已配置必要参数"""
        return bool(self.config.get('app_key'))

    def is_enabled(self):
        """检查是否启用"""
        return self.config.get('enabled', False) and self.is_configured()

    def _get_token(self):
        """[已废弃] 直接 Bearer AppKey 鉴权, 不再需要 TokenHub 换 token"""
        return self.config.get('app_key', '')

    def _call_ai(self, prompt, system_prompt=None):
        """调用AI端点 (直接 Bearer AppKey 鉴权, 无需 TokenHub)"""
        if not self.is_configured():
            return {
                'success': False,
                'error': 'AI未配置: 请在配置文件中填写app_key，并设置enabled=true',
                'analysis': ''
            }

        app_key = self.config.get('app_key', '')
        endpoint = self.config.get('endpoint', '')
        model_id = self.config.get('model_id', '')
        model_name = self.config.get('model_name', '')

        if not endpoint:
            return {
                'success': False,
                'error': 'AI端点未配置',
                'analysis': ''
            }

        # 构建消息
        messages = []
        if system_prompt:
            messages.append({
                'role': 'system',
                'content': system_prompt
            })
        messages.append({
            'role': 'user',
            'content': prompt
        })

        payload = json.dumps({
            'model': model_id or model_name,
            'messages': messages,
            'max_tokens': self.config.get('max_tokens', 8192),
            'temperature': self.config.get('temperature', 0.3),
            'stream': False,
        }).encode('utf-8')

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {app_key}',
        }

        req = urllib.request.Request(endpoint, data=payload, headers=headers, method='POST')

        try:
            with urllib.request.urlopen(req, timeout=self.config.get('timeout', 60)) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                # 兼容 OpenAI 与 Anthropic 返回格式
                if 'choices' in result and result['choices']:
                    content = result['choices'][0].get('message', {}).get('content', '')
                    return {
                        'success': True,
                        'error': None,
                        'analysis': content,
                        'usage': result.get('usage', {}),
                        'model': result.get('model', model_name),
                    }
                elif 'content' in result:
                    # Anthropic 格式: {"content": [{"type":"text","text":"..."}]}
                    content_parts = result.get('content', [])
                    if isinstance(content_parts, list):
                        content = ''.join(p.get('text', '') for p in content_parts if p.get('type') == 'text')
                    else:
                        content = str(content_parts)
                    return {
                        'success': True,
                        'error': None,
                        'analysis': content,
                        'usage': result.get('usage', {}),
                        'model': result.get('model', model_name),
                    }
                elif 'result' in result:
                    return {
                        'success': True,
                        'error': None,
                        'analysis': result.get('result', ''),
                        'model': model_name,
                    }
                else:
                    return {
                        'success': False,
                        'error': f'AI返回格式异常: {json.dumps(result, ensure_ascii=False)[:500]}',
                        'analysis': ''
                    }
        except urllib.error.HTTPError as e:
            error_body = ''
            try:
                error_body = e.read().decode('utf-8')
            except Exception:
                pass
            return {
                'success': False,
                'error': f'AI调用失败(HTTP {e.code}): {error_body[:500]}',
                'analysis': ''
            }
        except urllib.error.URLError as e:
            return {
                'success': False,
                'error': f'AI连接失败: {e.reason}',
                'analysis': ''
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'AI调用异常: {str(e)}',
                'analysis': ''
            }

    def analyze_process(self, proc_info):
        """
        分析单个高危进程
        proc_info: 进程详情 dict (来自 proc_monitor.get_all_processes)
        """
        system_prompt = (
            '你是一名专业的Linux系统安全分析师。请根据提供的进程信息，分析该进程是否存在安全风险，'
            '给出风险等级（高危/中危/低危/安全）、具体原因和处置建议。'
            '分析要点：\n'
            '1. 进程名是否为已知恶意软件或后门工具\n'
            '2. 可执行文件路径是否可疑（/tmp、/dev/shm等临时目录）\n'
            '3. 进程是否存在异常网络外连\n'
            '4. 启动用户是否异常（非root用户运行特权进程等）\n'
            '5. 是否有定时/自启配置\n'
            '6. 命令行参数是否包含可疑特征\n'
            '请以结构化格式输出：风险等级、分析结论、处置建议。'
        )

        prompt = self._build_process_prompt(proc_info)
        result = self._call_ai(prompt, system_prompt)
        result['target_type'] = 'process'
        result['target'] = f"{proc_info.get('name', '')}(PID:{proc_info.get('pid', '')})"
        result['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
        return result

    def analyze_connection(self, conn_info):
        """
        分析单个可疑网络连接
        conn_info: 连接详情 dict (来自 net_monitor.get_all_connections)
        """
        system_prompt = (
            '你是一名专业的网络安全分析师。请根据提供的网络连接信息，分析该连接是否存在安全风险，'
            '给出风险等级（高危/中危/低危/安全）、具体原因和处置建议。'
            '分析要点：\n'
            '1. 远程IP归属地是否为高风险地区\n'
            '2. 端口和协议是否为已知高危端口\n'
            '3. 连接方向是否异常（如内网服务器主动外连到未知IP）\n'
            '4. 进程是否为Shell/脚本类（可能为反弹Shell）\n'
            '5. 连接频率是否异常（高频外连可能为C2通信）\n'
            '6. 数据传输量是否异常\n'
            '请以结构化格式输出：风险等级、分析结论、处置建议。'
        )

        prompt = self._build_connection_prompt(conn_info)
        result = self._call_ai(prompt, system_prompt)
        result['target_type'] = 'connection'
        result['target'] = f"{conn_info.get('remote_ip', '')}:{conn_info.get('remote_port', '')}"
        result['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
        return result

    def analyze_batch(self, items, item_type='auto'):
        """
        批量分析多个高危项目
        items: list[dict] (进程或连接详情)
        item_type: 'process' / 'connection' / 'auto'(自动识别)
        """
        results = []
        for item in items:
            if item_type == 'process' or (item_type == 'auto' and 'pid' in item):
                results.append(self.analyze_process(item))
            elif item_type == 'connection' or (item_type == 'auto' and 'remote_ip' in item):
                results.append(self.analyze_connection(item))
            results.append(None)  # separator
        return [r for r in results if r is not None]

    def _build_process_prompt(self, p):
        """构建进程分析的 prompt"""
        lines = [
            '请分析以下Linux进程的安全风险：',
            '',
            f'进程名: {p.get("name", "未知")}',
            f'PID: {p.get("pid", "未知")}',
            f'父进程: {p.get("parent_name", "未知")}(PPID:{p.get("ppid", "")})',
            f'可执行文件: {p.get("exe", "未知")}',
            f'命令行: {p.get("cmdline", "未知")}',
            f'启动用户: {p.get("username", "未知")}',
            f'启动时间: {p.get("start_time", "未知")}',
            f'进程说明: {p.get("description", "未知")}',
            f'进程分类: {p.get("category", "未知")}',
            f'当前状态: {p.get("status", "未知")}',
            f'内存占用: {p.get("memory_rss_str", "未知")}',
            f'CPU使用率: {p.get("cpu_percent", 0)}%',
            f'运行时长: {p.get("uptime_str", "未知")}',
            '',
            f'关联进程(祖先链): {p.get("ancestors_str", "无")}',
            f'关联进程(子进程): {p.get("children_str", "无")}',
            '',
            f'定时启动配置: {p.get("schedule_str", "未知")}',
            '',
            f'网络端口: {p.get("net_ports_str", "无")}',
            f'网络连接: {p.get("net_conns_str", "无")}',
            '',
            f'已知风险标记: {p.get("risk_reasons_str", "无")}',
            f'风险等级(本地规则): {p.get("risk_level", "未知")}',
        ]
        return '\n'.join(lines)

    def _build_connection_prompt(self, c):
        """构建连接分析的 prompt"""
        geo = c.get('geo', {})
        freq = c.get('frequency', {})
        lines = [
            '请分析以下Linux网络连接的安全风险：',
            '',
            f'协议: {c.get("protocol", "未知")}',
            f'状态: {c.get("state", "未知")}',
            f'方向: {c.get("direction", "未知")}',
            '',
            f'本地地址: {c.get("local_ip", "")}:{c.get("local_port", "")}',
            f'远程地址: {c.get("remote_ip", "")}:{c.get("remote_port", "")}',
            f'数据类型: {c.get("data_type", "未知")}',
            f'对端操作系统: {c.get("remote_os", "未知")}',
            '',
            f'远程IP归属地: {geo.get("geo_str", "未知")}',
            f'对端经纬度: {geo.get("lng", "")},{geo.get("lat", "")}',
            '',
            f'关联进程: {c.get("process", "未知")}(PID:{c.get("pid", "")})',
            f'进程命令行: {c.get("process_cmdline", "未知")}',
            f'进程用户: {c.get("process_user", "未知")}',
            '',
            f'连接时长: {c.get("age_str", "未知")}',
            f'定时器信息: {c.get("timer_info", "无")}',
            '',
            f'已发送数据量: {c.get("bytes_sent_str", "0 B")}',
            f'已接收数据量: {c.get("bytes_recv_str", "0 B")}',
            '',
            f'连接频率: {freq.get("frequency_desc", "无数据")}',
            f'首次发现: {freq.get("first_seen", "未知")}',
            f'最后发现: {freq.get("last_seen", "未知")}',
            '',
            f'已知风险标记: {c.get("risk_reasons_str", "无")}',
            f'风险等级(本地规则): {c.get("risk_level", "未知")}',
        ]
        return '\n'.join(lines)

    def generate_security_report(self, processes=None, connections=None):
        """综合安全报告 — 对全部高危项进行一次性AI分析"""
        system_prompt = (
            '你是一名专业的Linux系统安全审计专家。请对以下系统进程和网络连接进行全面安全分析，'
            '生成一份安全审计报告。报告应包含：\n'
            '1. 总体安全评估（安全/需关注/存在风险/高危）\n'
            '2. 高危项目清单及详细分析\n'
            '3. 风险趋势分析\n'
            '4. 处置建议优先级排序\n'
            '5. 加固建议\n'
            '请用中文回答，条理清晰。'
        )

        sections = []

        if processes:
            risky_procs = [p for p in processes if p.get('is_risky') or p.get('risk_level') in ('high', 'medium')]
            if risky_procs:
                sections.append('=== 高危/可疑进程 ===')
                for p in risky_procs[:10]:  # 限制最多10个，避免token过多
                    sections.append(self._build_process_prompt(p))
                    sections.append('---')

        if connections:
            risky_conns = [c for c in connections if c.get('risk_level') in ('high', 'medium')]
            if risky_conns:
                sections.append('=== 可疑网络连接 ===')
                for c in risky_conns[:20]:
                    sections.append(self._build_connection_prompt(c))
                    sections.append('---')

        if not sections:
            return {
                'success': True,
                'error': None,
                'analysis': '当前系统未检测到高危进程或可疑网络连接，系统安全状态良好。',
                'target_type': 'overview',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            }

        prompt = '请对以下系统安全检测结果进行全面分析：\n\n' + '\n'.join(sections)
        result = self._call_ai(prompt, system_prompt)
        result['target_type'] = 'overview'
        result['target'] = '系统综合安全报告'
        result['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
        return result


# 全局实例
_analyzer = None


def get_analyzer(config_path=None):
    global _analyzer
    if _analyzer is None or config_path:
        _analyzer = AIAnalyzer(config_path)
    return _analyzer
