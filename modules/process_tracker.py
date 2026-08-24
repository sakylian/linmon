"""Portable, sampling-based suspicious-process tracker.

It uses psutil so the same baseline works on Linux, Windows and macOS.  File
counts are observed open-file snapshots, not kernel audit events; the report
states this limitation explicitly.
"""

import threading
import time
import uuid
from collections import Counter
from datetime import datetime

import psutil

from .geo_locator import is_valid_public_ip


def _fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


class ProcessTracker:
    def __init__(self, max_sessions=50, max_running=5):
        self.max_sessions = max_sessions
        self.max_running = max_running
        self._sessions = {}
        self._lock = threading.RLock()

    def start(self, pid, duration=60, interval=2.0):
        pid, duration, interval = int(pid), int(duration), float(interval)
        if duration < 5 or duration > 3600:
            raise ValueError('跟踪时长必须在 5 到 3600 秒之间')
        if interval < 0.5 or interval > 60:
            raise ValueError('采样间隔必须在 0.5 到 60 秒之间')
        if pid <= 0:
            raise ValueError('PID 必须是正整数')
        proc = psutil.Process(pid)
        sid = uuid.uuid4().hex[:12]
        now = time.time()
        session = {
            'id': sid, 'pid': pid, 'process_name': proc.name(),
            'process_create_time': proc.create_time(),
            'started_at': now, 'started_at_str': _fmt_ts(now),
            'duration': duration, 'interval': interval, 'status': 'running',
            'sample_count': 0, 'unique_files': set(), 'file_observations': 0,
            'endpoints': Counter(), 'public_endpoints': Counter(),
            'connection_states': Counter(), 'first_io': None, 'last_io': None,
            'cpu_samples': [], 'memory_peak': 0, 'errors': [], 'stop': False,
        }
        with self._lock:
            if sum(1 for s in self._sessions.values() if s['status'] == 'running') >= self.max_running:
                raise ValueError(f'同时最多跟踪 {self.max_running} 个进程')
            self._sessions[sid] = session
            self._trim()
        thread = threading.Thread(target=self._run, args=(sid,), daemon=True,
                                  name=f'linmon-track-{pid}')
        thread.start()
        return self.get(sid)

    def _trim(self):
        if len(self._sessions) <= self.max_sessions:
            return
        finished = sorted((s for s in self._sessions.values() if s['status'] != 'running'),
                          key=lambda s: s['started_at'])
        for s in finished[:max(0, len(self._sessions) - self.max_sessions)]:
            self._sessions.pop(s['id'], None)

    def _run(self, sid):
        with self._lock:
            session = self._sessions[sid]
        deadline = session['started_at'] + session['duration']
        try:
            proc = psutil.Process(session['pid'])
            proc.cpu_percent(None)
            while time.time() < deadline:
                with self._lock:
                    if session['stop']:
                        session['status'] = 'stopped'
                        break
                if proc.create_time() != session['process_create_time']:
                    raise psutil.NoSuchProcess(session['pid'], 'PID 已被复用')
                self._sample(proc, session)
                threading.Event().wait(min(session['interval'], max(0, deadline - time.time())))
            else:
                session['status'] = 'completed'
        except psutil.NoSuchProcess:
            session['status'] = 'process_exited'
        except (psutil.AccessDenied, OSError) as exc:
            session['status'] = 'limited'
            session['errors'].append(str(exc))
        finally:
            ended = time.time()
            session['ended_at'] = ended
            session['ended_at_str'] = _fmt_ts(ended)

    @staticmethod
    def _io_dict(proc):
        try:
            io = proc.io_counters()
            return {k: int(getattr(io, k, 0) or 0) for k in
                    ('read_count', 'write_count', 'read_bytes', 'write_bytes')}
        except (psutil.AccessDenied, AttributeError, NotImplementedError):
            return None

    def _sample(self, proc, session):
        try:
            files = proc.open_files()
            paths = [f.path for f in files if getattr(f, 'path', '')]
            remaining = max(0, 10000 - len(session['unique_files']))
            session['unique_files'].update(paths[:remaining])
            if len(paths) > remaining and '文件路径记录达到 10000 条上限' not in session['errors']:
                session['errors'].append('文件路径记录达到 10000 条上限')
            session['file_observations'] += len(files)
        except (psutil.AccessDenied, NotImplementedError):
            if '无法读取打开文件列表（权限或平台限制）' not in session['errors']:
                session['errors'].append('无法读取打开文件列表（权限或平台限制）')
        try:
            conns = proc.connections(kind='inet')
            for c in conns:
                session['connection_states'][c.status or 'NONE'] += 1
                if not c.raddr:
                    continue
                ip, port = c.raddr.ip, int(c.raddr.port)
                key = f'{ip}:{port}'
                session['endpoints'][key] += 1
                if is_valid_public_ip(ip):
                    session['public_endpoints'][key] += 1
        except (psutil.AccessDenied, NotImplementedError):
            if '无法读取进程连接（权限或平台限制）' not in session['errors']:
                session['errors'].append('无法读取进程连接（权限或平台限制）')
        io = self._io_dict(proc)
        if io:
            session['first_io'] = session['first_io'] or io
            session['last_io'] = io
        try:
            session['cpu_samples'].append(float(proc.cpu_percent(None)))
            session['memory_peak'] = max(session['memory_peak'], proc.memory_info().rss)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        session['sample_count'] += 1

    def stop(self, sid):
        with self._lock:
            if sid not in self._sessions:
                raise KeyError(sid)
            self._sessions[sid]['stop'] = True
            return self._serialize(self._sessions[sid])

    def get(self, sid):
        with self._lock:
            if sid not in self._sessions:
                raise KeyError(sid)
            return self._serialize(self._sessions[sid])

    def list(self):
        with self._lock:
            return [self._serialize(s) for s in sorted(
                self._sessions.values(), key=lambda x: x['started_at'], reverse=True)]

    @staticmethod
    def _serialize(s):
        elapsed = max(0, (s.get('ended_at') or time.time()) - s['started_at'])
        io_delta = {}
        if s['first_io'] and s['last_io']:
            io_delta = {k: max(0, s['last_io'][k] - s['first_io'][k]) for k in s['first_io']}
        endpoints = [{'remote': k, 'observations': v, 'public': k in s['public_endpoints']}
                     for k, v in s['endpoints'].most_common()]
        return {
            'id': s['id'], 'pid': s['pid'], 'process_name': s['process_name'],
            'status': s['status'], 'started_at': s['started_at_str'],
            'ended_at': s.get('ended_at_str'), 'duration': s['duration'],
            'elapsed_seconds': round(elapsed, 1), 'interval': s['interval'],
            'sample_count': s['sample_count'],
            'files': {'unique_observed': len(s['unique_files']),
                      'open_file_observations': s['file_observations'],
                      'paths': sorted(s['unique_files'])[:200],
                      'measurement': '采样时观察到的打开文件，不等同于内核审计记录的全部文件访问'},
            'network': {'unique_endpoints': len(s['endpoints']),
                        'public_endpoints': len(s['public_endpoints']),
                        'endpoints': endpoints,
                        'state_observations': dict(s['connection_states'])},
            'io_delta': io_delta,
            'cpu': {'average_percent': round(sum(s['cpu_samples']) / len(s['cpu_samples']), 1)
                    if s['cpu_samples'] else 0,
                    'peak_sample_percent': round(max(s['cpu_samples']), 1) if s['cpu_samples'] else 0},
            'memory_peak_bytes': s['memory_peak'], 'errors': list(s['errors']),
        }

    def report(self, sid):
        data = self.get(sid)
        net = data['network']
        files = data['files']
        public = [e for e in net['endpoints'] if e['public']]
        concerns = []
        if public:
            concerns.append(f'观察到 {len(public)} 个公网对端，需确认是否符合该程序用途。')
        if public and max(e['observations'] for e in public) >= max(3, data['sample_count'] // 2):
            concerns.append('该进程在多数采样中持续对外通信。')
        if files['unique_observed'] > 100:
            concerns.append('观察到的文件范围较大，建议核对文件路径是否与程序用途一致。')
        if not concerns:
            concerns.append('本次采样未发现明显的持续外连或大范围文件活动。')
        actions = [
            '先核对进程名称、可执行文件路径、启动用户和父进程是否可信。',
            '不认识公网对端时，可先停止程序或断网，再用杀毒软件进行全盘扫描。',
            '需要完整文件访问证据时，请使用 Linux audit/eBPF、Windows ETW/Sysmon 或 macOS Endpoint Security。',
        ]
        return {'title': '可疑进程跟踪简报', 'tracking': data,
                'summary': f"已跟踪 {data['process_name']} (PID {data['pid']}) {data['elapsed_seconds']} 秒；"
                           f"观察到 {files['unique_observed']} 个不同文件、{net['unique_endpoints']} 个网络对端。",
                'concerns': concerns, 'recommended_actions': actions,
                'ai_ready': True}


tracker = ProcessTracker()
