#!/usr/bin/env python3
"""
distro_helper.py — 发行版适配模块
支持 Debian 系 (Ubuntu/Debian) 和 CentOS 系 (RHEL/CentOS/Rocky/AlmaLinux)
"""

import os
import subprocess
import platform
import shutil
from pathlib import Path


class DistroHelper:
    """统一封装不同 Linux 发行版的差异"""

    def __init__(self):
        self._distro_info = None

    @property
    def distro_info(self):
        if self._distro_info is None:
            self._distro_info = self._detect_distro()
        return self._distro_info

    def _detect_distro(self):
        """检测当前发行版信息"""
        info = {
            'family': 'unknown',      # debian / rhel / arch / suse
            'id': '',                 # ubuntu, debian, centos, rhel, rocky, almalinux
            'version': '',            # 22.04, 11, 9
            'name': '',               # Ubuntu 22.04 LTS
            'pkg_manager': '',        # apt / dnf / yum / pacman / zypper
            'service_manager': 'systemd',  # systemd / sysvinit / openrc
        }

        # 方法1: 读取 /etc/os-release (现代Linux标准)
        os_release = {}
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line:
                        key, val = line.split('=', 1)
                        os_release[key.strip()] = val.strip().strip('"')
        except FileNotFoundError:
            pass

        if os_release:
            distro_id = os_release.get('ID', '').lower()
            id_like = os_release.get('ID_LIKE', '').lower()

            # 判断发行版家族
            if distro_id in ('debian', 'ubuntu', 'linuxmint', 'kali', 'raspbian') or 'debian' in id_like:
                info['family'] = 'debian'
                info['pkg_manager'] = 'apt'
            elif distro_id in ('centos', 'rhel', 'rocky', 'almalinux', 'fedora', 'ol') or 'rhel' in id_like or 'fedora' in id_like:
                info['family'] = 'rhel'
                if distro_id == 'fedora' or self._version_ge(os_release.get('VERSION_ID', ''), '8'):
                    info['pkg_manager'] = 'dnf'
                else:
                    info['pkg_manager'] = 'yum'
            elif distro_id in ('arch', 'manjaro', 'endeavouros') or 'arch' in id_like:
                info['family'] = 'arch'
                info['pkg_manager'] = 'pacman'
            elif distro_id in ('opensuse', 'suse', 'sles') or 'suse' in id_like:
                info['family'] = 'suse'
                info['pkg_manager'] = 'zypper'

            info['id'] = distro_id
            info['version'] = os_release.get('VERSION_ID', '')
            info['name'] = os_release.get('PRETTY_NAME', platform.platform())

        # 方法2: 回退到 platform 模块
        if not info['id']:
            raw = platform.platform().lower()
            if 'debian' in raw or 'ubuntu' in raw:
                info['family'] = 'debian'
                info['pkg_manager'] = 'apt'
                info['id'] = 'debian' if 'debian' in raw else 'ubuntu'
            elif 'centos' in raw:
                info['family'] = 'rhel'
                info['pkg_manager'] = 'yum'
                info['id'] = 'centos'

        # 服务管理器检测
        if shutil.which('systemctl'):
            info['service_manager'] = 'systemd'
        elif shutil.which('service'):
            info['service_manager'] = 'sysvinit'
        else:
            info['service_manager'] = 'unknown'

        return info

    @staticmethod
    def _version_ge(v1, v2):
        """比较版本号 v1 >= v2"""
        try:
            parts1 = [int(x) for x in v1.split('.')]
            parts2 = [int(x) for x in v2.split('.')]
            for i in range(max(len(parts1), len(parts2))):
                a = parts1[i] if i < len(parts1) else 0
                b = parts2[i] if i < len(parts2) else 0
                if a > b:
                    return True
                if a < b:
                    return False
            return True
        except (ValueError, IndexError):
            return False

    def get_family(self):
        return self.distro_info['family']

    def get_id(self):
        return self.distro_info['id']

    def get_name(self):
        return self.distro_info['name']

    def get_pkg_manager(self):
        return self.distro_info['pkg_manager']

    def get_service_manager(self):
        return self.distro_info['service_manager']

    def install_package(self, pkg_name):
        """安装包（各发行版命令不同）"""
        mgr = self.distro_info['pkg_manager']
        if mgr == 'apt':
            subprocess.run(['sudo', 'apt-get', 'update', '-qq'], capture_output=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y', pkg_name], capture_output=True)
        elif mgr == 'dnf':
            subprocess.run(['sudo', 'dnf', 'install', '-y', pkg_name], capture_output=True)
        elif mgr == 'yum':
            subprocess.run(['sudo', 'yum', 'install', '-y', pkg_name], capture_output=True)
        elif mgr == 'pacman':
            subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', pkg_name], capture_output=True)
        elif mgr == 'zypper':
            subprocess.run(['sudo', 'zypper', 'install', '-y', pkg_name], capture_output=True)

    def check_package_installed(self, pkg_name):
        """检查包是否已安装"""
        mgr = self.distro_info['pkg_manager']
        if mgr == 'apt':
            r = subprocess.run(['dpkg', '-s', pkg_name], capture_output=True, text=True)
            return r.returncode == 0
        elif mgr in ('dnf', 'yum'):
            r = subprocess.run(['rpm', '-q', pkg_name], capture_output=True, text=True)
            return r.returncode == 0
        elif mgr == 'pacman':
            r = subprocess.run(['pacman', '-Q', pkg_name], capture_output=True, text=True)
            return r.returncode == 0
        elif mgr == 'zypper':
            r = subprocess.run(['zypper', 'search', '-i', pkg_name], capture_output=True, text=True)
            return r.returncode == 0 and 'No matching packages' not in r.stdout
        return False

    def get_cron_dirs(self):
        """获取定时任务配置目录列表"""
        dirs = [
            '/etc/crontab',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly'
        ]
        # user crontabs
        user_cron = '/var/spool/cron/crontabs'
        if not os.path.exists(user_cron):
            user_cron = '/var/spool/cron'  # RHEL系路径
            dirs.append(user_cron)
        else:
            dirs.append(user_cron)
        return dirs

    def get_systemd_timers(self):
        """获取 systemd 定时器列表"""
        timers = []
        if self.distro_info['service_manager'] != 'systemd':
            return timers
        try:
            r = subprocess.run(
                ['systemctl', 'list-timers', '--all', '--no-pager', '--output=json'],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0 and r.stdout.strip():
                import json
                from datetime import datetime
                raw_timers = json.loads(r.stdout)
                # 格式化时间戳（systemctl --output=json 返回微秒级时间戳）
                for t in raw_timers:
                    for key in ('next', 'last', 'next_elapse', 'last_trigger'):
                        val = t.get(key)
                        if val and isinstance(val, (int, float)):
                            # 微秒时间戳 → 可读时间
                            try:
                                t[key] = datetime.fromtimestamp(val / 1e6).strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, OSError):
                                pass
                    timers.append(t)
        except Exception:
            pass
        return timers

    def get_systemd_services_running(self):
        """获取正在运行的 systemd 服务列表"""
        services = []
        if self.distro_info['service_manager'] != 'systemd':
            return services
        try:
            r = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running',
                 '--no-pager', '--no-legend'],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                for line in r.stdout.strip().split('\n'):
                    parts = line.split()
                    if parts:
                        services.append(parts[0])
        except Exception:
            pass
        return services

    def get_rc_local(self):
        """读取 /etc/rc.local 启动脚本内容"""
        content = ''
        try:
            with open('/etc/rc.local', 'r') as f:
                content = f.read()
        except (FileNotFoundError, PermissionError):
            pass
        return content

    def get_initd_scripts(self):
        """获取 /etc/init.d/ 下的启动脚本列表"""
        scripts = []
        try:
            for entry in os.listdir('/etc/init.d'):
                full = os.path.join('/etc/init.d', entry)
                if os.path.isfile(full) and os.access(full, os.X_OK):
                    scripts.append(entry)
        except (FileNotFoundError, PermissionError):
            pass
        return scripts

    def get_firewall_status(self):
        """获取防火墙状态"""
        result = {
            'type': 'unknown',
            'active': False,
            'rules': []
        }
        # ufw (Debian系常用)
        if shutil.which('ufw'):
            result['type'] = 'ufw'
            r = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True)
            if r.returncode == 0:
                result['active'] = 'Status: active' in r.stdout
                for line in r.stdout.split('\n'):
                    if line.strip() and not line.startswith('Status') and not line.startswith('Logging'):
                        result['rules'].append(line.strip())
        # firewalld (RHEL系常用)
        elif shutil.which('firewall-cmd'):
            result['type'] = 'firewalld'
            r = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True)
            result['active'] = r.returncode == 0 and 'running' in r.stdout
            if result['active']:
                r = subprocess.run(['firewall-cmd', '--list-all'], capture_output=True, text=True)
                if r.returncode == 0:
                    result['rules'] = r.stdout.strip().split('\n')
        # iptables
        if shutil.which('iptables'):
            r = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                if not result['active']:
                    result['type'] = 'iptables'
                    result['active'] = True
                    result['rules'] = r.stdout.strip().split('\n')
        return result


# 全局实例
_distro = None


def get_distro():
    global _distro
    if _distro is None:
        _distro = DistroHelper()
    return _distro
