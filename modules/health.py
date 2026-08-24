"""Beginner-friendly system health summary built from local scan results."""


def build_health_report(processes, connections, boot_info=None):
    """Return a conservative health score plus plain-language explanations."""
    real_processes = [p for p in (processes or []) if not p.get('is_monitor_owned')]
    real_connections = [c for c in (connections or []) if not c.get('is_monitor_owned')]
    high_p = [p for p in real_processes if p.get('risk_level') == 'high']
    medium_p = [p for p in real_processes if p.get('risk_level') == 'medium']
    high_c = [c for c in real_connections if c.get('risk_level') == 'high']
    medium_c = [c for c in real_connections if c.get('risk_level') == 'medium']

    penalty = min(50, len(high_p) * 20) + min(20, len(medium_p) * 5)
    penalty += min(20, len(high_c) * 10) + min(10, len(medium_c) * 2)
    score = max(0, 100 - penalty)
    if high_p or high_c:
        level, headline = 'danger', '发现需要尽快确认的高风险活动'
    elif medium_p or medium_c:
        level, headline = 'attention', '系统基本可用，但有项目需要核实'
    else:
        level, headline = 'healthy', '当前未发现明显异常'

    findings = []
    if high_p:
        names = ', '.join(f"{p.get('name', '?')} (PID {p.get('pid', '?')})" for p in high_p[:3])
        findings.append({'severity': 'high', 'title': '高风险进程',
                         'plain': f'有 {len(high_p)} 个进程行为异常：{names}。'})
    if high_c:
        targets = ', '.join(f"{c.get('remote_ip', '?')}:{c.get('remote_port', 0)}" for c in high_c[:3])
        findings.append({'severity': 'high', 'title': '高风险网络通信',
                         'plain': f'有 {len(high_c)} 组网络通信需要确认：{targets}。'})
    if medium_p or medium_c:
        findings.append({'severity': 'medium', 'title': '待确认项目',
                         'plain': f'另有 {len(medium_p)} 个进程和 {len(medium_c)} 组连接需要人工确认。'})
    if not findings:
        findings.append({'severity': 'low', 'title': '扫描结果正常',
                         'plain': '没有发现已知恶意特征或明显异常外连。'})

    actions = []
    if high_p:
        actions.append('先不要直接删除文件；选择可疑进程进行一段时间跟踪，确认它访问的文件和网络对端。')
    if high_c:
        actions.append('核对高风险连接对应的程序；不认识时先断网或停止该程序，再做进一步检查。')
    if not actions:
        actions.append('保持监控运行并定期复查；“未发现异常”不等于绝对安全。')

    return {
        'score': score,
        'level': level,
        'headline': headline,
        'findings': findings,
        'recommended_actions': actions,
        'counts': {
            'high_processes': len(high_p), 'medium_processes': len(medium_p),
            'high_connections': len(high_c), 'medium_connections': len(medium_c),
            'monitor_safe_items': sum(1 for p in (processes or []) if p.get('is_monitor_owned'))
                                  + sum(1 for c in (connections or []) if c.get('is_monitor_owned')),
        },
        'note': '健康评分是帮助初学者理解当前扫描结果的提示，不替代专业杀毒或取证。',
    }
