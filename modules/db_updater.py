#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
db_updater.py — 数据库更新 (参考 nali 的数据库获取逻辑)

支持获取:
  - qqwry.dat   IPv4 纯真库 (https://github.com/metowolf/qqwry.dat 发布)
  - ipv6wry.db  IPv6 ZX 库   (https://ip.zxinc.org/ip.7z 内成员，需 7z 解压)
  - cdn.yml     CDN 厂商域名库 (jsdelivr / github 多个回退源)

保存目录默认 <项目>/data/。可用 `linmon update` 调用。
"""
import os
import sys
import shutil
import tempfile
import urllib.request
import urllib.error

from .geo_locator import DATA_DIR

# 下载源 (与 nali 一致，含多个回退源)
QQWRY_URL = 'https://github.com/metowolf/qqwry.dat/releases/latest/download/qqwry.dat'
IPV6_7Z_URL = 'https://ip.zxinc.org/ip.7z'
IPV6_MEMBER = 'ipv6wry.db'

CDN_URLS = [
    'https://cdn.jsdelivr.net/gh/4ft35t/cdn/src/cdn.yml',
    'https://raw.githubusercontent.com/4ft35t/cdn/main/src/cdn.yml',
    'https://raw.githubusercontent.com/SukkaW/Sukka-CDN-Domains/master/cdn.yml',
]

# ip.7z 解压工具优先级: 7z CLI > py7zr
VALID_DB = {'qqwry', 'cdn', 'zxipv6wry'}


def _print(msg):
    print(msg, flush=True)


def _http_download(url, dest, timeout=60):
    """下载 url 到 dest，返回 True/False。"""
    req = urllib.request.Request(url, headers={'User-Agent': 'linmon-db-updater/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    tmp = dest + '.part'
    with open(tmp, 'wb') as f:
        f.write(data)
    os.replace(tmp, dest)
    return True


def _extract_ipv6_7z(archive_path, out_path):
    """从 ip.7z 中抽取 ipv6wry.db 到 out_path。优先 7z CLI，回退 py7zr。"""
    # 1) 7z CLI
    seven_zip = shutil.which('7z') or shutil.which('7za') or shutil.which('7zr')
    if seven_zip:
        tmp_dir = tempfile.mkdtemp(prefix='linmon_ipv6_')
        try:
            code = os.system(f'"{seven_zip}" x -y -o"{tmp_dir}" "{archive_path}" "{IPV6_MEMBER}" >/dev/null 2>&1')
            member = os.path.join(tmp_dir, IPV6_MEMBER)
            if code == 0 and os.path.isfile(member):
                shutil.copyfile(member, out_path)
                return True
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    # 2) py7zr 回退
    try:
        import py7zr  # type: ignore
    except ImportError:
        return False
    with py7zr.SevenZipFile(archive_path, mode='r') as z:
        names = z.getnames()
        target = next((n for n in names if n.endswith(IPV6_MEMBER)), None)
        if not target:
            return False
        tmp_dir = tempfile.mkdtemp(prefix='linmon_ipv6_')
        try:
            z.extract(path=tmp_dir, targets=[target])
            member = os.path.join(tmp_dir, target)
            if os.path.isfile(member):
                shutil.copyfile(member, out_path)
                return True
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    return False


def update_qqwry(data_dir=DATA_DIR):
    dest = os.path.join(data_dir, 'qqwry.dat')
    _print(f'[qqwry] 下载 IPv4 纯真库 ...')
    try:
        _http_download(QQWRY_URL, dest, timeout=120)
    except (urllib.error.URLError, OSError) as e:
        _print(f'[qqwry] 下载失败: {e}')
        return False
    size = os.path.getsize(dest)
    _print(f'[qqwry] 完成: {dest} ({size // 1024} KiB)')
    return True


def update_ipv6(data_dir=DATA_DIR):
    dest = os.path.join(data_dir, 'ipv6wry.db')
    _print(f'[zxipv6wry] 下载 ip.7z ...')
    archive = os.path.join(tempfile.gettempdir(), 'linmon_ip.7z')
    try:
        _http_download(IPV6_7Z_URL, archive, timeout=120)
    except (urllib.error.URLError, OSError) as e:
        _print(f'[zxipv6wry] 下载失败: {e}')
        return False
    _print(f'[zxipv6wry] 解压 {IPV6_MEMBER} ...')
    if not _extract_ipv6_7z(archive, dest):
        _print('[zxipv6wry] 解压失败: 需要 7z 命令行工具或 py7zr 库')
        return False
    size = os.path.getsize(dest)
    _print(f'[zxipv6wry] 完成: {dest} ({size // 1024} KiB)')
    return True


def update_cdn(data_dir=DATA_DIR):
    dest = os.path.join(data_dir, 'cdn.yml')
    for url in CDN_URLS:
        _print(f'[cdn] 尝试 {url}')
        try:
            _http_download(url, dest, timeout=60)
            size = os.path.getsize(dest)
            _print(f'[cdn] 完成: {dest} ({size // 1024} KiB)')
            return True
        except (urllib.error.URLError, OSError) as e:
            _print(f'[cdn] 失败: {e}')
            continue
    _print('[cdn] 所有源均失败')
    return False


def update_databases(db_list=None, data_dir=DATA_DIR):
    """更新数据库。db_list 为子集 {'qqwry','cdn','zxipv6wry'}，None 表示全部。"""
    if db_list is None:
        db_list = list(VALID_DB)
    db_list = [d for d in db_list if d in VALID_DB]
    if not db_list:
        _print('无有效的数据库可更新')
        return False
    os.makedirs(data_dir, exist_ok=True)
    results = {}
    for db in db_list:
        if db == 'qqwry':
            results['qqwry'] = update_qqwry(data_dir)
        elif db == 'zxipv6wry':
            results['zxipv6wry'] = update_ipv6(data_dir)
        elif db == 'cdn':
            results['cdn'] = update_cdn(data_dir)
    ok = all(results.values())
    _print('')
    _print('更新结果:')
    for k, v in results.items():
        _print(f'  {k}: {"成功" if v else "失败"}')
    return ok


if __name__ == '__main__':
    # 直接运行: python -m modules.db_updater
    target = sys.argv[1:] or None
    if target:
        target = [t for t in target if t in VALID_DB]
    update_databases(target)
