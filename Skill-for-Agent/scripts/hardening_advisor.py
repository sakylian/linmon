#!/usr/bin/env python3
"""
hardening_advisor.py — 系统加固建议生成器 (跨平台: Linux/macOS/Windows)

功能:
  1. 检查当前系统的安全配置状态（防火墙、SSH/远程桌面、用户权限、内核参数等）
  2. 基于扫描结果生成针对性的加固建议
  3. 输出结构化 JSON 供 LLM 进一步分析

合规设计:
  - 仅检查和读取系统配置，不修改任何系统设置
  - 不含任何攻击性工具或渗透测试功能
  - 建议基于公开的安全最佳实践 (CIS Benchmarks / NIST 通用标准)
"""

import os
import sys
import json
import subprocess
import time
import platform

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

IS_WINDOWS = sys.platform == 'win32'
IS_MACOS = sys.platform == 'darwin'
IS_LINUX = sys.platform.startswith('linux')


def _run_cmd(cmd, timeout=5):
    """安全运行命令，返回 stdout 或空串"""
    try:
        kwargs = dict(capture_output=True, text=True, timeout=timeout)
        if IS_WINDOWS:
            kwargs['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        r = subprocess.run(cmd, **kwargs)
        return r.stdout.strip() if r.returncode == 0 else ''
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ''


# ──────────────────────── 防火墙检查 ────────────────────────

def check_firewall_status():
    """检查防火墙状态（跨平台）"""
    result = {'tool': 'none', 'status': 'unknown', 'details': ''}

    if IS_WINDOWS:
        return _check_firewall_windows()
    elif IS_MACOS:
        return _check_firewall_macos()
    else:
        return _check_firewall_linux()


def _check_firewall_linux():
    """Linux 防火墙检查"""
    result = {'tool': 'none', 'status': 'unknown', 'details': ''}

    out = _run_cmd(['ufw', 'status'])
    if out:
        result['tool'] = 'ufw'
        result['status'] = 'active' if 'Status: active' in out else 'inactive'
        result['details'] = out[:200]
        return result

    out = _run_cmd(['firewall-cmd', '--state'])
    if out:
        result['tool'] = 'firewalld'
        result['status'] = out
        return result

    out = _run_cmd(['iptables', '-L', '-n'])
    if out:
        result['tool'] = 'iptables'
        lines = out.split('\n')
        result['status'] = f'{len(lines)} rules'
        result['details'] = f'{len(lines)} 条规则'
        return result

    result['status'] = '未检测到防火墙'
    return result


def _check_firewall_macos():
    """macOS 防火墙检查"""
    result = {'tool': 'none', 'status': 'unknown', 'details': ''}

    # Application Firewall
    out = _run_cmd(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'])
    if out:
        result['tool'] = 'Application Firewall'
        result['status'] = 'active' if 'enabled' in out.lower() else 'inactive'
        return result

    # pf
    out = _run_cmd(['pfctl', '-s', 'info'])
    if out:
        if 'Status: Enabled' in out:
            result['tool'] = 'pf'
            result['status'] = 'active'
        elif 'Status: Disabled' in out:
            result['tool'] = 'pf'
            result['status'] = 'inactive'
        return result

    result['status'] = '未检测到防火墙'
    return result


def _check_firewall_windows():
    """Windows 防火墙检查"""
    result = {'tool': 'Windows Defender Firewall', 'status': 'unknown', 'details': ''}
    profiles = {'domain': 'unknown', 'private': 'unknown', 'public': 'unknown'}

    out = _run_cmd(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], timeout=10)
    if out:
        current_profile = None
        for line in out.split('\n'):
            line = line.strip()
            low = line.lower()
            if 'profile configuration' in low or 'profile settings' in low:
                parts = line.split()
                if parts:
                    current_profile = parts[0].lower()
            elif current_profile:
                if 'OFF' in line.upper():
                    profiles[current_profile] = 'inactive'
                elif 'ON' in line.upper():
                    profiles[current_profile] = 'active'

    active_count = sum(1 for v in profiles.values() if v == 'active')
    if active_count == 3:
        result['status'] = 'active'
    elif active_count == 0:
        result['status'] = 'inactive'
    else:
        result['status'] = 'partial'
    result['details'] = f"Domain={profiles['domain']}, Private={profiles['private']}, Public={profiles['public']}"
    return result


# ──────────────────────── SSH / 远程桌面检查 ────────────────────────

def check_ssh_config():
    """检查 SSH 配置安全 (Linux/macOS)"""
    checks = {
        'root_login': 'unknown',
        'password_auth': 'unknown',
        'port': '22',
        'permit_empty_passwords': 'unknown',
        'x11_forwarding': 'unknown',
        'max_auth_tries': 'unknown',
    }

    if IS_WINDOWS:
        return checks  # Windows 没有 SSH 服务端配置（除非装了 OpenSSH）

    import re as _re
    sshd_config = '/etc/ssh/sshd_config'
    sshd_dir = '/etc/ssh/sshd_config.d'

    content = ''
    if os.path.isfile(sshd_config):
        try:
            with open(sshd_config, 'r') as f:
                content = f.read()
        except (OSError, PermissionError):
            pass

    if os.path.isdir(sshd_dir):
        for fn in os.listdir(sshd_dir):
            if fn.endswith('.conf'):
                try:
                    with open(os.path.join(sshd_dir, fn), 'r') as f:
                        content += '\n' + f.read()
                except (OSError, PermissionError):
                    continue

    if content:
        m = _re.search(r'(?m)^PermitRootLogin\s+(\S+)', content)
        if m:
            checks['root_login'] = m.group(1)

        m = _re.search(r'(?m)^PasswordAuthentication\s+(\S+)', content)
        if m:
            checks['password_auth'] = m.group(1)

        m = _re.search(r'(?m)^Port\s+(\d+)', content)
        if m:
            checks['port'] = m.group(1)

        m = _re.search(r'(?m)^PermitEmptyPasswords\s+(\S+)', content)
        if m:
            checks['permit_empty_passwords'] = m.group(1)

        m = _re.search(r'(?m)^X11Forwarding\s+(\S+)', content)
        if m:
            checks['x11_forwarding'] = m.group(1)

        m = _re.search(r'(?m)^MaxAuthTries\s+(\d+)', content)
        if m:
            checks['max_auth_tries'] = m.group(1)

    return checks


def check_rdp_config():
    """检查 Windows RDP 配置"""
    checks = {
        'enabled': 'unknown',
        'nla_required': 'unknown',
        'firewall_allowed': 'unknown',
    }

    if not IS_WINDOWS:
        return checks

    # 检查 RDP 是否启用
    out = _run_cmd(['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
                    '/v', 'fDenyTSConnections'], timeout=5)
    if out:
        if '0x1' in out:
            checks['enabled'] = 'disabled'
        elif '0x0' in out:
            checks['enabled'] = 'enabled'

    # 检查 NLA (Network Level Authentication)
    out = _run_cmd(['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
                    '/v', 'UserAuthentication'], timeout=5)
    if out:
        if '0x1' in out:
            checks['nla_required'] = 'yes'
        elif '0x0' in out:
            checks['nla_required'] = 'no'

    return checks


# ──────────────────────── 用户安全检查 ────────────────────────

def check_user_security():
    """检查用户账户安全（跨平台）"""
    if IS_WINDOWS:
        return _check_user_security_windows()
    else:
        return _check_user_security_unix()


def _check_user_security_unix():
    """Linux/macOS 用户安全"""
    checks = {
        'users_with_shell': [],
        'users_with_uid0': [],
        'password_empty_users': [],
        'total_users': 0,
    }

    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) < 7:
                    continue
                username, _, uid, _, _, _, shell = parts
                checks['total_users'] += 1
                if shell and shell not in ('/bin/false', '/usr/sbin/nologin', '/bin/nologin', ''):
                    checks['users_with_shell'].append(username)
                if uid == '0' and username != 'root':
                    checks['users_with_uid0'].append(username)
    except (OSError, PermissionError):
        pass

    out = _run_cmd(['awk', '-F:', '($2==""){print $1}', '/etc/shadow'])
    if out:
        checks['password_empty_users'] = out.split('\n')

    return checks


def _check_user_security_windows():
    """Windows 用户安全"""
    checks = {
        'users_with_shell': [],
        'users_with_uid0': [],
        'password_empty_users': [],
        'total_users': 0,
        'admin_accounts': [],
    }

    # 列出本地用户
    out = _run_cmd(['net', 'user'], timeout=10)
    if out:
        lines = out.split('\n')
        # net user 输出: 用户名在中间行，以 ---- 分隔
        collecting = False
        for line in lines:
            if '---' in line:
                collecting = not collecting
                continue
            if collecting:
                for name in line.split():
                    if name and name not in ('命令', 'The', 'command', '----------'):
                        checks['users_with_shell'].append(name)
                        checks['total_users'] += 1

    # 检查管理员组成员
    out = _run_cmd(['net', 'localgroup', 'Administrators'], timeout=10)
    if out:
        lines = out.split('\n')
        collecting = False
        for line in lines:
            if '---' in line:
                collecting = not collecting
                continue
            if collecting:
                name = line.strip()
                if name and name not in ('命令', 'The', 'command', '----------'):
                    checks['admin_accounts'].append(name)

    return checks


# ──────────────────────── 内核参数检查 ────────────────────────

def check_kernel_params():
    """检查内核安全参数 (仅 Linux)"""
    params = {
        'ip_forward': 'unknown',
        'tcp_syncookies': 'unknown',
        'icmp_echo_ignore_broadcasts': 'unknown',
        'accept_source_route': 'unknown',
        'accept_redirects': 'unknown',
        'send_redirects': 'unknown',
        'rp_filter': 'unknown',
    }

    if not IS_LINUX:
        return params

    param_map = {
        'ip_forward': 'net.ipv4.ip_forward',
        'tcp_syncookies': 'net.ipv4.tcp_syncookies',
        'icmp_echo_ignore_broadcasts': 'net.ipv4.icmp_echo_ignore_broadcasts',
        'accept_source_route': 'net.ipv4.conf.all.accept_source_route',
        'accept_redirects': 'net.ipv4.conf.all.accept_redirects',
        'send_redirects': 'net.ipv4.conf.all.send_redirects',
        'rp_filter': 'net.ipv4.conf.all.rp_filter',
    }

    for key, sysctl_name in param_map.items():
        out = _run_cmd(['sysctl', '-n', sysctl_name])
        if out:
            params[key] = out

    return params


def check_macos_security():
    """检查 macOS 专属安全配置"""
    checks = {
        'gatekeeper': 'unknown',
        'sip': 'unknown',
        'filevault': 'unknown',
        'auto_updates': 'unknown',
    }

    if not IS_MACOS:
        return checks

    # Gatekeeper
    out = _run_cmd(['spctl', '--status'])
    if out:
        checks['gatekeeper'] = 'enabled' if 'enabled' in out.lower() else 'disabled'

    # SIP (System Integrity Protection)
    out = _run_cmd(['csrutil', 'status'])
    if out:
        checks['sip'] = 'enabled' if 'enabled' in out.lower() else 'disabled'

    # FileVault
    out = _run_cmd(['fdesetup', 'status'])
    if out:
        checks['filevault'] = 'on' if 'On' in out else 'off'

    # Software auto-update
    out = _run_cmd(['defaults', 'read', '/Library/Preferences/com.apple.SoftwareUpdate',
                    'AutomaticCheckEnabled'])
    if out:
        checks['auto_updates'] = 'enabled' if '1' in out else 'disabled'

    return checks


def check_windows_security():
    """检查 Windows 专属安全配置"""
    checks = {
        'uac': 'unknown',
        'windows_defender': 'unknown',
        'auto_update': 'unknown',
        'screensaver_lock': 'unknown',
    }

    if not IS_WINDOWS:
        return checks

    # UAC (User Account Control)
    out = _run_cmd(['reg', 'query',
                    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                    '/v', 'EnableLUA'], timeout=5)
    if out:
        checks['uac'] = 'enabled' if '0x1' in out else 'disabled'

    # Windows Defender
    out = _run_cmd(['powershell', '-Command',
                    '(Get-MpComputerStatus).AntivirusEnabled'], timeout=10)
    if out:
        checks['windows_defender'] = 'enabled' if 'True' in out else 'disabled'

    # Windows Auto Update
    out = _run_cmd(['reg', 'query',
                    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',
                    '/v', 'AUOptions'], timeout=5)
    if out:
        if '0x4' in out:
            checks['auto_update'] = 'auto_install'
        elif '0x3' in out:
            checks['auto_update'] = 'notify'
        elif '0x1' in out:
            checks['auto_update'] = 'disabled'

    return checks


# ──────────────────────── 失败登录检查 ────────────────────────

def check_failed_logins():
    """检查最近的失败登录（跨平台）"""
    checks = {
        'recent_failed': 0,
        'last_failed_user': '',
        'last_failed_time': '',
    }

    if IS_WINDOWS:
        out = _run_cmd(['wevtutil', 'qe', 'Security',
                        '/q:*[System[(EventID=4625)]]', '/c:20', '/rd:true',
                        '/f:text'], timeout=10)
        if out:
            lines = [l for l in out.split('\n') if l.strip()]
            checks['recent_failed'] = len(lines) // 10  # 每个事件约 10 行
            for line in lines:
                if 'Account Name' in line or '帐户名' in line:
                    parts = line.split()
                    if parts:
                        checks['last_failed_user'] = parts[-1]
                    break
    else:
        out = _run_cmd(['lastb', '-n', '20'])
        if out:
            lines = [l for l in out.split('\n') if l.strip()]
            checks['recent_failed'] = len(lines)
            if lines:
                parts = lines[0].split()
                if parts:
                    checks['last_failed_user'] = parts[0]

    return checks


# ──────────────────────── MAC / SELinux 检查 ────────────────────────

def check_selinux_apparmor():
    """检查 SELinux/AppArmor 状态 (仅 Linux)"""
    result = {'mac': 'none', 'status': 'unknown'}

    if not IS_LINUX:
        return result

    # SELinux
    out = _run_cmd(['getenforce'])
    if out:
        result['mac'] = 'SELinux'
        result['status'] = out
        return result

    # AppArmor
    if os.path.isdir('/sys/kernel/security/apparmor'):
        result['mac'] = 'AppArmor'
        profiles = _run_cmd(['aa-status', '--profiled'])
        if profiles:
            result['status'] = f'{profiles} profiles loaded'
        else:
            result['status'] = 'loaded'
        return result

    return result


def check_auto_updates():
    """检查自动更新配置（跨平台）"""
    if IS_WINDOWS:
        ws = check_windows_security()
        return {
            'configured': ws.get('auto_update') in ('auto_install', 'notify'),
            'tool': 'Windows Update',
            'details': ws.get('auto_update', 'unknown'),
        }
    elif IS_MACOS:
        ms = check_macos_security()
        return {
            'configured': ms.get('auto_updates') == 'enabled',
            'tool': 'Software Update',
            'details': ms.get('auto_updates', 'unknown'),
        }
    else:
        result = {'configured': False, 'tool': 'none', 'details': ''}
        if os.path.isfile('/etc/apt/apt.conf.d/50unattended-upgrades'):
            result['configured'] = True
            result['tool'] = 'unattended-upgrades'
            result['details'] = '已配置自动安全更新'
        elif os.path.isfile('/etc/dnf/automatic.conf'):
            result['configured'] = True
            result['tool'] = 'dnf-automatic'
            result['details'] = '已配置 dnf 自动更新'
        return result


# ──────────────────────── 建议生成 ────────────────────────

def generate_hardening_advice(scan_summary=None):
    """
    基于系统检查和扫描结果生成加固建议（跨平台）
    """
    checks = {
        'firewall': check_firewall_status(),
        'ssh': check_ssh_config(),
        'rdp': check_rdp_config() if IS_WINDOWS else None,
        'users': check_user_security(),
        'kernel': check_kernel_params() if IS_LINUX else None,
        'failed_logins': check_failed_logins(),
        'mac': check_selinux_apparmor() if IS_LINUX else None,
        'macos_security': check_macos_security() if IS_MACOS else None,
        'windows_security': check_windows_security() if IS_WINDOWS else None,
        'auto_updates': check_auto_updates(),
    }

    advice = []

    if IS_LINUX:
        advice = _generate_linux_advice(checks, scan_summary)
    elif IS_MACOS:
        advice = _generate_macos_advice(checks, scan_summary)
    elif IS_WINDOWS:
        advice = _generate_windows_advice(checks, scan_summary)

    # ── 基于扫描结果的建议（所有平台通用）──
    if scan_summary:
        s = scan_summary.get('summary', {})

        if s.get('high_risk_processes', 0) > 0:
            advice.append({
                'priority': 'critical',
                'category': '威胁处置',
                'title': '立即处置高危进程',
                'description': f'扫描发现 {s["high_risk_processes"]} 个高危进程，建议立即核实并处置。',
                'commands': ['# 使用 security_scan.py --processes --json 查看详情'] +
                            (['# 终止进程: Stop-Process -Id <PID> -Force'] if IS_WINDOWS else
                             ['# 确认恶意后终止进程: kill -9 <PID>',
                              '# 检查持久化: crontab -l, systemctl list-unit-files --state=enabled']),
            })

        if s.get('high_risk_connections', 0) > 0:
            advice.append({
                'priority': 'critical',
                'category': '威胁处置',
                'title': '阻断高危网络连接',
                'description': f'扫描发现 {s["high_risk_connections"]} 条高危网络连接，建议立即排查。',
                'commands': ['# 使用 security_scan.py --connections --json 查看详情'] +
                            (['# 阻断连接: New-NetFirewallRule -Direction Outbound -RemoteAddress <IP> -Action Block'] if IS_WINDOWS else
                             ['# 阻断连接: sudo iptables -A OUTPUT -d <恶意IP> -j DROP',
                              '# 使用 route_trace.py 追踪连接路径']),
            })

        if s.get('high_risk_listening_ports', 0) > 0:
            advice.append({
                'priority': 'high',
                'category': '端口管理',
                'title': '关闭不必要的高危监听端口',
                'description': f'发现 {s["high_risk_listening_ports"]} 个高危监听端口，建议关闭不必要的服务。',
                'commands': ['# 查看监听端口: security_scan.py --listening'] +
                            (['# 防火墙封禁: New-NetFirewallRule -Direction Inbound -LocalPort <port> -Action Block'] if IS_WINDOWS else
                             ['# 关闭服务: sudo systemctl stop <service> && sudo systemctl disable <service>',
                              '# 防火墙封禁: sudo ufw deny <port>']),
            })

    # 按优先级排序
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    advice.sort(key=lambda a: priority_order.get(a['priority'], 99))

    return {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'platform': platform.platform(),
        'checks': checks,
        'advice': advice,
    }


def _generate_linux_advice(checks, scan_summary):
    """Linux 加固建议"""
    advice = []

    # ── 防火墙 ──
    fw = checks['firewall']
    if fw['status'] in ('inactive', '未检测到防火墙', 'unknown'):
        advice.append({
            'priority': 'high',
            'category': '防火墙',
            'title': '启用防火墙',
            'description': '当前系统未启用防火墙，所有端口暴露在网络中。建议立即启用 ufw 或 firewalld。',
            'commands': [
                'sudo apt install ufw && sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable',
                'sudo firewall-cmd --permanent --add-service=ssh && sudo firewall-cmd --reload',
            ],
        })

    # ── SSH ──
    ssh = checks['ssh']
    if ssh['root_login'] == 'yes':
        advice.append({
            'priority': 'high',
            'category': 'SSH',
            'title': '禁止 root 直接登录',
            'description': '当前允许 root 通过 SSH 直接登录，存在暴力破解风险。建议使用普通用户 + sudo。',
            'commands': ['sudo sed -i "s/^#*PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config && sudo systemctl restart sshd'],
        })

    if ssh['password_auth'] == 'yes':
        advice.append({
            'priority': 'medium',
            'category': 'SSH',
            'title': '禁用 SSH 密码认证，使用密钥登录',
            'description': '当前 SSH 允许密码登录，容易遭受暴力破解。建议配置密钥认证后禁用密码。',
            'commands': [
                '# 1. 先在客户端生成密钥并拷贝到服务器:\n#    ssh-keygen -t ed25519 && ssh-copy-id user@host',
                '# 2. 然后在服务器禁用密码认证:\n'
                'sudo sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config && sudo systemctl restart sshd',
            ],
        })

    if ssh['permit_empty_passwords'] == 'yes':
        advice.append({
            'priority': 'high',
            'category': 'SSH',
            'title': '禁止空密码登录',
            'description': 'SSH 允许空密码登录，极度危险。',
            'commands': ['sudo sed -i "s/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/" /etc/ssh/sshd_config && sudo systemctl restart sshd'],
        })

    if ssh['port'] == '22' and ssh['root_login'] != 'no':
        advice.append({
            'priority': 'low',
            'category': 'SSH',
            'title': '考虑修改默认 SSH 端口',
            'description': '使用默认 22 端口容易成为自动扫描攻击目标。修改为非标准端口可减少噪音。',
            'commands': ['sudo sed -i "s/^#*Port .*/Port 2222/" /etc/ssh/sshd_config && sudo systemctl restart sshd'],
        })

    # ── 用户安全 ──
    users = checks['users']
    if users['users_with_uid0']:
        advice.append({
            'priority': 'high',
            'category': '用户安全',
            'title': '检查非 root 的 UID=0 用户',
            'description': f'发现非 root 用户拥有 UID=0: {", ".join(users["users_with_uid0"])}。这可能是后门账户。',
            'commands': [f'sudo usermod -u 1000 {u}' for u in users['users_with_uid0']],
        })

    if users['password_empty_users']:
        advice.append({
            'priority': 'high',
            'category': '用户安全',
            'title': '设置空密码账户的密码',
            'description': f'发现空密码用户: {", ".join(users["password_empty_users"])}。',
            'commands': [f'sudo passwd {u}' for u in users['password_empty_users']],
        })

    if len(users['users_with_shell']) > 10:
        advice.append({
            'priority': 'low',
            'category': '用户安全',
            'title': '精简可登录用户',
            'description': f'当前有 {len(users["users_with_shell"])} 个用户可登录 shell。',
            'commands': ['# 将不需要交互登录的用户的 shell 改为 nologin:\n# sudo usermod -s /usr/sbin/nologin username'],
        })

    # ── 内核参数 ──
    kernel = checks['kernel']
    if kernel['ip_forward'] == '1':
        advice.append({
            'priority': 'medium',
            'category': '内核安全',
            'title': '非路由服务器请关闭 IP 转发',
            'description': 'net.ipv4.ip_forward=1 表示允许 IP 转发，非路由/VPN 服务器应关闭。',
            'commands': ['sudo sysctl -w net.ipv4.ip_forward=0 && echo "net.ipv4.ip_forward=0" | sudo tee -a /etc/sysctl.d/99-security.conf'],
        })

    if kernel['tcp_syncookies'] == '0':
        advice.append({
            'priority': 'medium',
            'category': '内核安全',
            'title': '启用 TCP SYN Cookies',
            'description': 'SYN Cookies 可防御 SYN Flood 攻击。',
            'commands': ['sudo sysctl -w net.ipv4.tcp_syncookies=1 && echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.d/99-security.conf'],
        })

    if kernel['accept_redirects'] in ('1', 'unknown'):
        advice.append({
            'priority': 'low',
            'category': '内核安全',
            'title': '禁用 ICMP 重定向接受',
            'description': '接受 ICMP 重定向可能被利用进行中间人攻击。',
            'commands': [
                'sudo sysctl -w net.ipv4.conf.all.accept_redirects=0',
                'sudo sysctl -w net.ipv6.conf.all.accept_redirects=0',
                'echo -e "net.ipv4.conf.all.accept_redirects=0\nnet.ipv6.conf.all.accept_redirects=0" | sudo tee -a /etc/sysctl.d/99-security.conf',
            ],
        })

    if kernel['accept_source_route'] in ('1', 'unknown'):
        advice.append({
            'priority': 'low',
            'category': '内核安全',
            'title': '禁用源路由',
            'description': '源路由数据包可被用于绕过安全控制。',
            'commands': [
                'sudo sysctl -w net.ipv4.conf.all.accept_source_route=0',
                'echo "net.ipv4.conf.all.accept_source_route=0" | sudo tee -a /etc/sysctl.d/99-security.conf',
            ],
        })

    # ── MAC ──
    mac = checks['mac']
    if mac['mac'] == 'none':
        advice.append({
            'priority': 'medium',
            'category': '访问控制',
            'title': '启用 SELinux 或 AppArmor',
            'description': '未检测到强制访问控制 (MAC) 机制。建议启用 AppArmor 或 SELinux 增强系统安全。',
            'commands': [
                '# Debian/Ubuntu:\nsudo apt install apparmor apparmor-utils && sudo systemctl enable apparmor',
                '# RHEL/CentOS:\nsudo setenforce 1 && sudo sed -i "s/SELINUX=permissive/SELINUX=enforcing/" /etc/selinux/config',
            ],
        })

    # ── 自动更新 ──
    if not checks['auto_updates']['configured']:
        advice.append({
            'priority': 'medium',
            'category': '系统更新',
            'title': '配置自动安全更新',
            'description': '未配置自动安全更新，系统可能遗漏关键补丁。',
            'commands': [
                '# Debian/Ubuntu:\nsudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades',
                '# RHEL/Fedora:\nsudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic.timer',
            ],
        })

    # ── 失败登录 ──
    failed = checks['failed_logins']
    if failed['recent_failed'] > 20:
        advice.append({
            'priority': 'medium',
            'category': '入侵防护',
            'title': '安装 fail2ban 防暴力破解',
            'description': f'检测到最近有大量失败登录 ({failed["recent_failed"]} 次)，建议安装 fail2ban 自动封禁。',
            'commands': [
                'sudo apt install fail2ban',
                'sudo systemctl enable --now fail2ban',
            ],
        })

    return advice


def _generate_macos_advice(checks, scan_summary):
    """macOS 加固建议"""
    advice = []

    # ── 防火墙 ──
    fw = checks['firewall']
    if fw['status'] in ('inactive', '未检测到防火墙', 'unknown'):
        advice.append({
            'priority': 'high',
            'category': '防火墙',
            'title': '启用应用层防火墙',
            'description': 'macOS 应用层防火墙未启用，建议立即开启。',
            'commands': [
                'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on',
                '# 或在 系统设置 > 网络 > 防火墙 中开启',
            ],
        })

    # ── Gatekeeper ──
    ms = checks.get('macos_security', {})
    if ms.get('gatekeeper') == 'disabled':
        advice.append({
            'priority': 'high',
            'category': '应用安全',
            'title': '启用 Gatekeeper',
            'description': 'Gatekeeper 已禁用，允许运行未签名的应用程序，存在恶意软件风险。',
            'commands': ['sudo spctl --master-enable'],
        })

    # ── SIP ──
    if ms.get('sip') == 'disabled':
        advice.append({
            'priority': 'high',
            'category': '系统完整性',
            'title': '启用 SIP (System Integrity Protection)',
            'description': 'SIP 已禁用，系统关键目录不受保护。建议在恢复模式中重新启用。',
            'commands': ['# 重启进入恢复模式 → 终端 → csrutil enable → 重启'],
        })

    # ── FileVault ──
    if ms.get('filevault') == 'off':
        advice.append({
            'priority': 'medium',
            'category': '磁盘加密',
            'title': '启用 FileVault 磁盘加密',
            'description': 'FileVault 未启用，磁盘数据未加密，设备丢失后数据可被读取。',
            'commands': ['sudo fdesetup enable'],
        })

    # ── SSH ──
    ssh = checks['ssh']
    if ssh['root_login'] == 'yes':
        advice.append({
            'priority': 'high',
            'category': 'SSH',
            'title': '禁止 root SSH 登录',
            'description': '允许 root 通过 SSH 直接登录存在暴力破解风险。',
            'commands': ['sudo sed -i "s/^#*PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config && sudo launchctl stop com.openssh.sshd'],
        })

    if ssh['password_auth'] == 'yes':
        advice.append({
            'priority': 'medium',
            'category': 'SSH',
            'title': '禁用 SSH 密码认证',
            'description': 'SSH 允许密码登录，建议配置密钥认证后禁用。',
            'commands': ['sudo sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config'],
        })

    # ── 自动更新 ──
    if not checks['auto_updates']['configured']:
        advice.append({
            'priority': 'medium',
            'category': '系统更新',
            'title': '启用自动更新',
            'description': '未配置自动更新，可能遗漏安全补丁。',
            'commands': [
                'sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true',
                'sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true',
            ],
        })

    return advice


def _generate_windows_advice(checks, scan_summary):
    """Windows 加固建议"""
    advice = []

    # ── 防火墙 ──
    fw = checks['firewall']
    if fw['status'] in ('inactive', 'unknown'):
        advice.append({
            'priority': 'high',
            'category': '防火墙',
            'title': '启用 Windows Defender 防火墙',
            'description': 'Windows 防火墙未启用，所有端口暴露在网络中。',
            'commands': [
                'netsh advfirewall set allprofiles state on',
                '# 或在 设置 > 隐私和安全性 > Windows 安全中心 > 防火墙和网络保护 中开启',
            ],
        })
    elif fw['status'] == 'partial':
        advice.append({
            'priority': 'medium',
            'category': '防火墙',
            'title': '为所有网络配置文件启用防火墙',
            'description': f'部分网络配置文件防火墙未启用: {fw["details"]}',
            'commands': ['netsh advfirewall set allprofiles state on'],
        })

    # ── UAC ──
    ws = checks.get('windows_security', {})
    if ws.get('uac') == 'disabled':
        advice.append({
            'priority': 'high',
            'category': '访问控制',
            'title': '启用 UAC (用户账户控制)',
            'description': 'UAC 已禁用，所有程序以管理员权限运行，增加恶意软件风险。',
            'commands': [
                '# 设置 > 账户 > 用户账户控制设置 → 调至默认级别',
            ],
        })

    # ── Windows Defender ──
    if ws.get('windows_defender') == 'disabled':
        advice.append({
            'priority': 'high',
            'category': '防病毒',
            'title': '启用 Windows Defender',
            'description': 'Windows Defender 防病毒已禁用。',
            'commands': [
                'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"',
            ],
        })

    # ── RDP ──
    rdp = checks.get('rdp', {})
    if rdp.get('enabled') == 'enabled':
        if rdp.get('nla_required') != 'yes':
            advice.append({
                'priority': 'high',
                'category': '远程桌面',
                'title': '要求 RDP 网络级认证 (NLA)',
                'description': 'RDP 已启用但未要求 NLA，容易遭受暴力破解和中间人攻击。',
                'commands': [
                    '# 系统属性 > 远程 → 仅允许使用 NLA 的远程桌面计算机连接',
                    'reg add \\\\HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp /v UserAuthentication /t REG_DWORD /d 1 /f',
                ],
            })
        advice.append({
            'priority': 'medium',
            'category': '远程桌面',
            'title': '确认 RDP 暴露范围',
            'description': 'RDP 已启用，确保仅在内网或通过 VPN 访问，不要直接暴露到公网。',
            'commands': ['# 检查防火墙规则: netsh advfirewall firewall show rule name=all | findstr RDP'],
        })

    # ── 自动更新 ──
    if not checks['auto_updates']['configured']:
        advice.append({
            'priority': 'medium',
            'category': '系统更新',
            'title': '启用 Windows 自动更新',
            'description': '未配置自动更新，可能遗漏安全补丁。',
            'commands': [
                '# 设置 > 更新和安全 > Windows 更新 → 高级选项 → 启用自动下载和安装',
            ],
        })

    # ── 用户安全 ──
    users = checks['users']
    if len(users.get('admin_accounts', [])) > 3:
        advice.append({
            'priority': 'medium',
            'category': '用户安全',
            'title': '精简管理员账户',
            'description': f'管理员组中有 {len(users["admin_accounts"])} 个成员: {", ".join(users["admin_accounts"][:5])}',
            'commands': ['# 使用 net localgroup Administrators <用户名> /delete 移除不需要的管理员'],
        })

    # ── 失败登录 ──
    failed = checks['failed_logins']
    if failed['recent_failed'] > 20:
        advice.append({
            'priority': 'medium',
            'category': '入侵防护',
            'title': '配置账户锁定策略',
            'description': f'检测到大量失败登录 ({failed["recent_failed"]} 次)，建议配置账户锁定策略。',
            'commands': [
                'net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30',
            ],
        })

    return advice


# ──────────────────────── CLI ────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description='系统安全加固建议生成器 (跨平台)')
    parser.add_argument('--json', action='store_true', help='输出 JSON 格式')
    parser.add_argument('--check-only', action='store_true', help='仅输出检查结果，不生成建议')
    args = parser.parse_args()

    result = generate_hardening_advice()

    if args.check_only:
        if args.json:
            print(json.dumps(result['checks'], ensure_ascii=False, indent=2, default=str))
        else:
            print(f'\n系统安全配置检查 — {result["timestamp"]}')
            print(f'平台: {result.get("platform", "unknown")}')
            print('=' * 60)

            fw = result['checks']['firewall']
            print(f'\n[防火墙] 工具: {fw["tool"]}  状态: {fw["status"]}')

            ssh = result['checks']['ssh']
            if ssh and ssh.get('port'):
                print(f'\n[SSH] 端口: {ssh["port"]}  root登录: {ssh["root_login"]}  '
                      f'密码认证: {ssh["password_auth"]}  空密码: {ssh["permit_empty_passwords"]}')

            rdp = result['checks'].get('rdp')
            if rdp:
                print(f'\n[RDP] 启用: {rdp["enabled"]}  NLA: {rdp["nla_required"]}')

            users = result['checks']['users']
            print(f'\n[用户] 总账户: {users["total_users"]}  可登录: {len(users["users_with_shell"])}  '
                  f'管理员: {users.get("admin_accounts", users.get("users_with_uid0", []))}')

            kernel = result['checks'].get('kernel')
            if kernel:
                print(f'\n[内核] ip_forward={kernel["ip_forward"]}  syncookies={kernel["tcp_syncookies"]}  '
                      f'redirects={kernel["accept_redirects"]}')

            mac = result['checks'].get('mac')
            if mac:
                print(f'\n[MAC] {mac["mac"]}: {mac["status"]}')

            ms = result['checks'].get('macos_security')
            if ms:
                print(f'\n[macOS] Gatekeeper: {ms["gatekeeper"]}  SIP: {ms["sip"]}  '
                      f'FileVault: {ms["filevault"]}')

            ws = result['checks'].get('windows_security')
            if ws:
                print(f'\n[Windows] UAC: {ws["uac"]}  Defender: {ws["windows_defender"]}  '
                      f'AutoUpdate: {ws["auto_update"]}')

            auto = result['checks']['auto_updates']
            print(f'\n[自动更新] {auto["tool"]}: {auto["details"] or "未配置"}')

            failed = result['checks']['failed_logins']
            print(f'\n[失败登录] 最近: {failed["recent_failed"]} 次  最后用户: {failed["last_failed_user"]}')
        return

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(f'\n系统加固建议 — {result["timestamp"]}')
        print(f'平台: {result.get("platform", "unknown")}')
        print('=' * 60)

        if not result['advice']:
            print('\n✓ 当前系统安全配置良好，未发现需要加固的项目。')
        else:
            for i, a in enumerate(result['advice'], 1):
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(a['priority'], '⚪')
                print(f'\n{i}. {icon} [{a["priority"].upper()}] {a["title"]}')
                print(f'   分类: {a["category"]}')
                print(f'   说明: {a["description"]}')
                if a.get('commands'):
                    for cmd in a['commands']:
                        print(f'   命令: {cmd}')


if __name__ == '__main__':
    main()
