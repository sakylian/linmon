#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
audit.py — 操作审计日志

记录敏感操作（向外部 LLM 发送数据、AI 配置变更、报告导出），
便于商业化部署后追溯"系统信息是否/何时被外发"。
日志写入 data/linmon-audit.log，不记录任何密钥或完整载荷。
"""

import os
import threading
from datetime import datetime

_lock = threading.Lock()
_AUDIT_PATH = None


def configure(path=None):
    """设置审计日志路径（默认 data/linmon-audit.log）"""
    global _AUDIT_PATH
    if path:
        _AUDIT_PATH = path
        return _AUDIT_PATH
    if _AUDIT_PATH is None:
        default = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'data', 'linmon-audit.log'
        )
        _AUDIT_PATH = default
    return _AUDIT_PATH


def log_event(event, detail='', user=None):
    """
    写入一条审计记录。
    event: 事件类型，如 'ai_send' / 'ai_send_blocked' / 'config_change' / 'report_export'
    detail: 人类可读的附加信息（不可含密钥或完整遥测）
    """
    configure()
    try:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f'{ts} | {event} | user={user or "unknown"} | {detail}\n'
        with _lock:
            with open(_AUDIT_PATH, 'a', encoding='utf-8') as f:
                f.write(line)
    except Exception:
        # 审计失败绝不能影响主流程
        pass
