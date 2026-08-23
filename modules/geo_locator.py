#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 linmon contributors
"""
geo_locator.py — IP归属地查询模块（统一模块，替代原来 sysdiag.py 和 netmap.py 中重复的实现）
支持纯真IP库(qqwry.dat)查询，含坐标映射
"""

import os
import struct
import socket
import ipaddress
from functools import lru_cache

# 内置地理坐标映射表（经纬度），覆盖中国主要城市和全球主要城市
GEO_COORDS = {
    # 中国城市
    '北京': (116.407, 39.904), '上海': (121.473, 31.230), '广州': (113.264, 23.129),
    '深圳': (114.057, 22.543), '杭州': (120.155, 30.274), '南京': (118.797, 32.060),
    '成都': (104.066, 30.572), '武汉': (114.305, 30.593), '西安': (108.940, 34.341),
    '重庆': (106.551, 29.563), '苏州': (120.585, 31.299), '天津': (117.201, 39.084),
    '青岛': (120.382, 36.067), '长沙': (112.939, 28.228), '郑州': (113.625, 34.748),
    '合肥': (117.227, 31.821), '济南': (117.000, 36.675), '南昌': (115.858, 28.683),
    '福州': (119.297, 26.075), '厦门': (118.089, 24.479), '昆明': (102.832, 24.880),
    '大连': (121.614, 38.914), '沈阳': (123.429, 41.796), '长春': (125.324, 43.886),
    '哈尔滨': (126.534, 45.803), '石家庄': (114.515, 38.048), '太原': (112.549, 37.857),
    '兰州': (103.834, 36.061), '贵阳': (106.713, 26.578), '南宁': (108.366, 22.817),
    '海口': (110.331, 20.032), '三亚': (109.508, 18.247), '拉萨': (91.140, 29.646),
    '银川': (106.231, 38.487), '西宁': (101.778, 36.617), '乌鲁木齐': (87.617, 43.793),
    '呼和浩特': (111.752, 40.842), '香港': (114.170, 22.320), '澳门': (113.543, 22.198),
    '台北': (121.565, 25.033), '高雄': (120.301, 22.627),
    # 福建各地市
    '漳州': (117.647, 24.513), '泉州': (118.589, 24.908), '莆田': (119.007, 25.431),
    '宁德': (119.527, 26.659), '龙岩': (117.017, 25.075), '三明': (117.638, 26.263),
    '南平': (118.178, 26.642), '福州': (119.297, 26.075),
    # 广东其他
    '东莞': (113.751, 23.021), '佛山': (113.122, 23.029), '珠海': (113.552, 22.256),
    '中山': (113.393, 22.518), '惠州': (114.412, 23.079), '汕头': (116.682, 23.354),
    '湛江': (110.358, 21.270),
    # 江苏其他
    '无锡': (120.312, 31.491), '南通': (120.865, 31.980), '徐州': (117.284, 34.206),
    '常州': (119.974, 31.812), '扬州': (119.421, 32.394),
    # 浙江其他
    '温州': (120.699, 27.994), '宁波': (121.544, 29.868), '绍兴': (120.580, 30.030),
    '嘉兴': (120.755, 30.746), '金华': (119.647, 29.079), '台州': (121.421, 28.656),
    # 山东其他
    '烟台': (121.448, 37.464), '威海': (122.116, 37.509), '潍坊': (119.107, 36.709),
    # 国际城市
    '东京': (139.692, 35.690), '大阪': (135.502, 34.693), '首尔': (126.978, 37.566),
    '新加坡': (103.820, 1.353), '曼谷': (100.502, 13.756), '吉隆坡': (101.687, 3.139),
    '雅加达': (106.845, -6.209), '马尼拉': (120.984, 14.599), '孟买': (72.877, 19.076),
    '新德里': (77.103, 28.704), '迪拜': (55.270, 25.204), '伊斯坦布尔': (28.979, 41.015),
    '伦敦': (-0.128, 51.508), '巴黎': (2.352, 48.857), '法兰克福': (8.682, 50.111),
    '阿姆斯特丹': (4.905, 52.371), '莫斯科': (37.618, 55.751), '斯德哥尔摩': (18.069, 59.329),
    '纽约': (-74.006, 40.713), '华盛顿': (-77.037, 38.907), '洛杉矶': (-118.244, 34.052),
    '旧金山': (-122.419, 37.775), '西雅图': (-122.332, 47.606), '芝加哥': (-87.650, 41.850),
    '达拉斯': (-96.797, 32.777), '亚特兰大': (-84.388, 33.749), '迈阿密': (-80.191, 25.762),
    '多伦多': (-79.347, 43.651), '温哥华': (-123.121, 49.283), '墨西哥城': (-99.133, 19.433),
    '圣保罗': (-46.634, -23.551), '布宜诺斯艾利斯': (-58.382, -34.604),
    '悉尼': (151.207, -33.868), '墨尔本': (144.963, -37.814), '奥克兰': (174.763, -36.849),
    '开普敦': (18.424, -33.925), '约翰内斯堡': (28.047, -26.204), '开罗': (31.236, 30.045),
    '内罗毕': (36.817, -1.286), '拉各斯': (3.379, 6.524), '卡萨布兰卡': (-7.589, 33.573),
}

# 国家名关键词 → 坐标
COUNTRY_KEYWORDS = {
    '美国': (-100.0, 40.0), '日本': (138.0, 36.0), '韩国': (127.5, 36.5),
    '英国': (-1.5, 53.0), '法国': (2.5, 47.0), '德国': (10.0, 51.0),
    '俄罗斯': (40.0, 60.0), '加拿大': (-100.0, 56.0), '澳大利亚': (134.0, -25.0),
    '印度': (79.0, 22.0), '巴西': (-55.0, -10.0), '新加坡': (103.8, 1.3),
    '荷兰': (5.7, 52.1), '瑞典': (15.0, 62.0), '瑞士': (8.2, 46.8),
    '爱尔兰': (-8.0, 53.3), '芬兰': (25.0, 64.0), '挪威': (10.0, 62.0),
    '丹麦': (9.5, 56.0), '波兰': (19.0, 52.0), '捷克': (15.5, 49.8),
    '奥地利': (14.5, 47.5), '比利时': (4.5, 50.6), '西班牙': (-3.7, 40.4),
    '意大利': (12.5, 42.0), '葡萄牙': (-8.2, 39.4), '希腊': (22.0, 39.0),
    '土耳其': (32.0, 39.0), '以色列': (35.0, 31.5), '阿联酋': (54.0, 24.0),
    '泰国': (101.0, 15.0), '越南': (107.0, 16.0), '马来西亚': (102.0, 4.0),
    '印度尼西亚': (113.0, -2.0), '菲律宾': (122.0, 13.0), '墨西哥': (-102.0, 23.0),
    '阿根廷': (-64.0, -34.0), '南非': (22.0, -30.0), '埃及': (30.0, 27.0),
    '蒙古': (103.8, 46.8), '哈萨克斯坦': (66.9, 48.0),
}


def is_private_ip(ip_str):
    """判断是否为私有IP"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (ValueError, TypeError):
        return False


def is_valid_public_ip(ip_str):
    """判断是否为有效的公网IP"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except (ValueError, TypeError):
        return False


class QqwryReader:
    """纯真IP数据库读取器"""

    def __init__(self, qqwry_path):
        self.path = qqwry_path
        self._fd = None
        self._index_count = 0
        self._loaded = False

    def load(self):
        try:
            self._fd = open(self.path, 'rb')
            buf = self._fd.read(8)
            self._first_index = struct.unpack('<I', buf[:4])[0]
            self._last_index = struct.unpack('<I', buf[4:8])[0]
            self._index_count = (self._last_index - self._first_index) // 7 + 1
            self._loaded = True
        except (FileNotFoundError, PermissionError) as e:
            raise FileNotFoundError(f'无法加载纯真IP库: {self.path} ({e})')

    def _read_string(self, offset):
        self._fd.seek(offset)
        data = b''
        while True:
            chunk = self._fd.read(1)
            if chunk == b'\x00' or not chunk:
                break
            data += chunk
        return data.decode('gb18030', errors='replace')

    def _read_area(self, offset):
        self._fd.seek(offset)
        byte = self._fd.read(1)
        if byte == b'\x01':
            ref = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
            if ref == 0:
                return ''
            return self._read_string(ref)
        elif byte == b'\x02':
            ref = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
            if ref == 0:
                return ''
            s = self._read_string(ref)
            self._read_string(offset + 4)  # skip redirect 2
            return s
        else:
            return self._read_string(offset)

    def _read_record(self, offset):
        self._fd.seek(offset + 4)
        byte = self._fd.read(1)
        if byte == b'\x01':
            ref = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
            return self._read_record(ref)
        elif byte == b'\x02':
            country_ref = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
            country = self._read_string(country_ref)
            area = self._read_area(offset + 4 + 4)
            return country, area
        else:
            country = self._read_string(offset + 4)
            area = self._read_area(self._fd.tell())
            return country, area

    def lookup(self, ip_str):
        """查询IP归属地，返回 (country, area)"""
        if not self._loaded:
            return '', ''
        try:
            ip_int = struct.unpack('>I', socket.inet_aton(ip_str))[0]
        except (OSError, struct.error):
            return '', ''

        lo, hi = 0, self._index_count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            offset = self._first_index + mid * 7
            self._fd.seek(offset)
            mid_ip = struct.unpack('>I', self._fd.read(4))[0]
            if ip_int < mid_ip:
                hi = mid - 1
            elif ip_int > mid_ip:
                lo = mid + 1
            else:
                record_offset = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
                return self._read_record(record_offset)

        if hi < 0:
            return '', ''
        offset = self._first_index + hi * 7
        self._fd.seek(offset + 4)
        record_offset = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
        return self._read_record(record_offset)

    def close(self):
        if self._fd:
            self._fd.close()
            self._loaded = False


DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))


def find_qqwry_dat():
    """搜索 qqwry.dat 文件"""
    search_paths = [
        os.path.join(DATA_DIR, 'qqwry.dat'),
        os.path.join(os.path.dirname(__file__), '..', 'qqwry.dat'),
        os.path.expanduser('~/qqwry.dat'),
        '/usr/share/qqwry/qqwry.dat',
        '/usr/local/share/qqwry.dat',
        '/etc/linmon/qqwry.dat',
    ]
    for p in search_paths:
        ap = os.path.abspath(p)
        if os.path.isfile(ap):
            return ap
    return None


def find_ipv6_db():
    """搜索 IPv6 地址库 ipv6wry.db 文件"""
    search_paths = [
        os.path.join(DATA_DIR, 'ipv6wry.db'),
        os.path.join(os.path.dirname(__file__), '..', 'ipv6wry.db'),
        os.path.expanduser('~/ipv6wry.db'),
        '/usr/share/linmon/ipv6wry.db',
        '/etc/linmon/ipv6wry.db',
    ]
    for p in search_paths:
        ap = os.path.abspath(p)
        if os.path.isfile(ap):
            return ap
    return None


def find_cdn_yaml():
    """搜索 CDN 厂商域名库 cdn.yml 文件"""
    search_paths = [
        os.path.join(DATA_DIR, 'cdn.yml'),
        os.path.join(os.path.dirname(__file__), '..', 'cdn.yml'),
        os.path.expanduser('~/cdn.yml'),
        '/usr/share/linmon/cdn.yml',
        '/etc/linmon/cdn.yml',
    ]
    for p in search_paths:
        ap = os.path.abspath(p)
        if os.path.isfile(ap):
            return ap
    return None


class Zxipv6wryReader:
    """ZX.IPv6 数据库读取器 (ip.zxinc.org, 格式见 ip.7z 内《格式详解-ipdb.txt》)

    文件头(小端序):
      0~3   "IPDB" 魔数
      4     minor 版本
      5     major 版本
      6     offset 长度 (offlen)
      7     IP 长度 (iplen, IPv6 仅用前 8 字节 = /64 前缀)
      8~15  int64 记录数
      16~23 int64 索引区首条偏移
    索引项 = IP[iplen] + offset[offlen] 字节；字符串为 UTF-8、以 \\0 结尾，
    支持 0x01/0x02 重定向(与 qqwry 类似)。
    """

    def __init__(self, db_path):
        self.path = db_path
        self._img = None
        self._loaded = False
        self._first_index = 0
        self._index_count = 0
        self._offlen = 3
        self._iplen = 8

    def _get_long8(self, offset, size=8):
        s = self._img[offset:offset + size]
        if len(s) < 8:
            s = s + b'\x00' * (8 - len(s))
        return struct.unpack_from('<Q', s)[0]

    def load(self):
        try:
            with open(self.path, 'rb') as f:
                self._img = f.read()
        except (FileNotFoundError, PermissionError) as e:
            raise FileNotFoundError(f'无法加载 IPv6 数据库: {self.path} ({e})')
        if self._img[:4] != b'IPDB':
            raise ValueError(f'IPv6 数据库格式错误(缺少 IPDB 魔数): {self.path}')
        self._offlen = self._img[6]
        self._iplen = self._img[7]
        self._index_count = self._get_long8(8)
        self._first_index = self._get_long8(16)
        self._loaded = True

    def _get_string(self, offset):
        if offset < 0 or offset >= len(self._img):
            return ''
        end = self._img.find(b'\x00', offset)
        if end == -1:
            end = len(self._img)
        raw = self._img[offset:end]
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return raw.decode('gb18030', errors='replace')

    def _get_area(self, offset):
        if offset < 0 or offset >= len(self._img):
            return ''
        byte = self._img[offset]
        if byte in (1, 2):
            p = self._get_long8(offset + 1, self._offlen)
            return self._get_area(p)
        return self._get_string(offset)

    def _get_addr(self, offset):
        img = self._img
        if offset < 0 or offset >= len(img):
            return '', ''
        byte = img[offset]
        if byte == 1:
            return self._get_addr(self._get_long8(offset + 1, self._offlen))
        country = self._get_area(offset)
        if byte == 2:
            o = offset + 1 + self._offlen
        else:
            n = img.find(b'\x00', offset)
            o = n + 1 if n != -1 else offset + 1
        area = self._get_area(o)
        return country, area

    def _find(self, ip_prefix, lo, hi):
        if hi - lo <= 1:
            return lo
        mid = (lo + hi) // 2
        o = self._first_index + mid * (self._iplen + self._offlen)
        mid_ip = self._get_long8(o, self._iplen)
        if ip_prefix < mid_ip:
            return self._find(ip_prefix, lo, mid)
        return self._find(ip_prefix, mid, hi)

    def lookup(self, ip_str):
        """查询 IPv6 归属地，返回 (country, area)"""
        if not self._loaded:
            return '', ''
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except (ValueError, TypeError):
            return '', ''
        if ip_obj.version != 6:
            return '', ''
        # 仅取高 64 位 (/64 前缀) 作为索引键
        ip_prefix = (int(ip_obj) >> 64) & 0xFFFFFFFFFFFFFFFF
        if self._index_count == 0:
            return '', ''
        i = self._find(ip_prefix, 0, self._index_count)
        ip_off = self._first_index + i * (self._iplen + self._offlen)
        rec_off = self._get_long8(ip_off + self._iplen, self._offlen)
        return self._get_addr(rec_off)

    def close(self):
        self._img = None
        self._loaded = False


# 内置 CDN 覆盖层：补充 cdn.yml 可能缺失的常用大厂域名。
# 仅当 cdn.yml 未包含该键时合入，保证 `linmon update` 拉取的社区数据优先。
_CDN_OVERLAY = {
    'qcloudcdn.com': {'name': '腾讯云 CDN', 'link': 'https://cloud.tencent.com/product/cdn'},
    'qcloud.com': {'name': '腾讯云', 'link': 'https://cloud.tencent.com'},
    'tencentcloud.com': {'name': '腾讯云', 'link': 'https://cloud.tencent.com'},
    'cloudflare.com': {'name': 'Cloudflare', 'link': 'https://www.cloudflare.com'},
    'akamai.com': {'name': 'Akamai CDN', 'link': 'https://www.akamai.com'},
}


class CdnMatcher:
    """CDN 厂商域名匹配器 (cdn.yml: domain -> {name, link})，按域名后缀最长匹配。"""

    def __init__(self):
        self._data = {}
        self._loaded = False
        self._path = None

    def load(self, path=None):
        path = path or find_cdn_yaml()
        if not path or not os.path.isfile(path):
            self._loaded = False
            return False
        self._path = path
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            self._loaded = False
            return False
        self._data = {str(k).lower(): v for k, v in data.items() if k}
        # 合入内置覆盖层：填补 cdn.yml 缺漏的常用 CDN 域名
        for dom, info in _CDN_OVERLAY.items():
            if dom not in self._data:
                self._data[dom] = info
        self._loaded = True
        return True

    def lookup(self, hostname):
        """根据主机名判断所属 CDN 厂商，返回 {provider, link, matched} 或 None"""
        if not self._loaded or not hostname:
            return None
        h = hostname.lower().strip().rstrip('.')
        best = None
        for domain in self._data:
            if h == domain or h.endswith('.' + domain):
                if best is None or len(domain) > len(best):
                    best = domain
        if best is None:
            return None
        info = self._data[best]
        if isinstance(info, dict):
            name = info.get('name') or best
            link = info.get('link') or ''
        else:
            name, link = info, ''
        return {'provider': name, 'link': link, 'matched': best}

    def close(self):
        self._data = {}
        self._loaded = False


_cdn_matcher = None


def cdn_lookup(hostname):
    """模块级 CDN 查询 (单例)；传入主机名返回 CDN 厂商信息或 None。"""
    global _cdn_matcher
    if _cdn_matcher is None:
        _cdn_matcher = CdnMatcher()
        _cdn_matcher.load()
    return _cdn_matcher.lookup(hostname)


def _reverse_dns(ip_str, timeout=0.5):
    """反向 DNS 解析主机名，失败返回空串。"""
    try:
        import socket
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyaddr(ip_str)[0]
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        return ''


def resolve_coordinates(geo_str):
    """将地理位置字符串解析为 (lng, lat) 坐标"""
    if not geo_str:
        return None, None

    # 1. 精确匹配城市名
    for city, coords in GEO_COORDS.items():
        if city in geo_str:
            return coords

    # 2. 国家关键词匹配
    for country, coords in COUNTRY_KEYWORDS.items():
        if country in geo_str:
            return coords

    # 3. 省份 + 方位推断 (如"福建省漳州" → 漳州)
    province_cities = {
        '福建': '福州', '广东': '广州', '浙江': '杭州', '江苏': '南京',
        '山东': '济南', '四川': '成都', '湖南': '长沙', '湖北': '武汉',
        '河南': '郑州', '河北': '石家庄', '安徽': '合肥', '江西': '南昌',
        '辽宁': '沈阳', '吉林': '长春', '黑龙江': '哈尔滨', '山西': '太原',
        '陕西': '西安', '甘肃': '兰州', '青海': '西宁', '云南': '昆明',
        '贵州': '贵阳', '广西': '南宁', '海南': '海口', '新疆': '乌鲁木齐',
        '内蒙古': '呼和浩特', '西藏': '拉萨', '宁夏': '银川',
    }
    for prov, cap in province_cities.items():
        if prov in geo_str and cap in GEO_COORDS:
            return GEO_COORDS[cap]

    return None, None


class GeoLocator:
    """统一的IP归属地查询器（IPv4/IPv6 + CDN 判断）"""

    _instance = None
    _reader = None          # IPv4 (QqwryReader)
    _reader6 = None         # IPv6 (Zxipv6wryReader)
    _qqwry_path = None
    _ipv6_path = None

    @classmethod
    def get_instance(cls, qqwry_path=None, ipv6_path=None):
        if cls._instance is None:
            cls._instance = cls()
        # IPv4 库
        if qqwry_path and qqwry_path != cls._qqwry_path:
            if cls._reader:
                cls._reader.close()
            cls._reader = None
            cls._qqwry_path = qqwry_path
        if cls._reader is None and (qqwry_path or find_qqwry_dat()):
            path = qqwry_path or find_qqwry_dat()
            try:
                cls._reader = QqwryReader(path)
                cls._reader.load()
                cls._qqwry_path = path
            except FileNotFoundError:
                cls._reader = None
        # IPv6 库
        if ipv6_path and ipv6_path != cls._ipv6_path:
            if cls._reader6:
                cls._reader6.close()
            cls._reader6 = None
            cls._ipv6_path = ipv6_path
        if cls._reader6 is None and (ipv6_path or find_ipv6_db()):
            path = ipv6_path or find_ipv6_db()
            try:
                cls._reader6 = Zxipv6wryReader(path)
                cls._reader6.load()
                cls._ipv6_path = path
            except (FileNotFoundError, ValueError):
                cls._reader6 = None
        return cls._instance

    @classmethod
    def lookup_ip(cls, ip_str, hostname=None, resolve_hostname=False):
        """查询IP归属地，返回 dict: country, area, coords, geo_str, cdn

        - hostname: 已知主机名时直接用于 CDN 判断（推荐，零额外开销）
        - resolve_hostname: 为 True 且无 hostname 时，对公网 IP 做一次反向 DNS
          （仅按需/少量使用，连接列表等批量场景请勿开启以免阻塞）
        """
        instance = cls.get_instance()
        country, area = '', ''
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            is_v6 = (ip_obj.version == 6)
        except (ValueError, TypeError):
            is_v6 = False

        if is_v6:
            if instance._reader6:
                country, area = instance._reader6.lookup(ip_str)
        else:
            if instance._reader:
                country, area = instance._reader.lookup(ip_str)

        geo_str = f'{country} {area}'.strip() if (country or area) else '未知'
        lng, lat = resolve_coordinates(geo_str)

        # CDN 判断：优先使用已知主机名，否则按需反向 DNS
        cdn = None
        if hostname is None and resolve_hostname and is_valid_public_ip(ip_str):
            hostname = _reverse_dns(ip_str)
        if hostname:
            cdn = cdn_lookup(hostname)

        result = {
            'ip': ip_str,
            'country': country,
            'area': area,
            'geo_str': geo_str,
            'lng': lng,
            'lat': lat,
        }
        if cdn:
            result['cdn'] = cdn
            result['cdn_node'] = True
            # CDN/云厂商边缘节点的 IP 归属地往往只是边缘机房位置，
            # 与真实业务所在地可能不同，需提示不可直接用于"境内/境外"判定
            result['geo_note'] = ('该 IP 属于 CDN/云厂商边缘节点，IP 归属地仅供参考，'
                                  '可能与真实业务所在地不同')
        return result

    @classmethod
    def close(cls):
        if cls._reader:
            cls._reader.close()
            cls._reader = None
        if cls._reader6:
            cls._reader6.close()
            cls._reader6 = None


# 端口→协议映射表
PORT_PROTOCOL_MAP = {
    20: ('FTP-DATA', 'medium'), 21: ('FTP', 'high'), 22: ('SSH', 'high'),
    23: ('Telnet', 'high'), 25: ('SMTP', 'medium'), 53: ('DNS', 'low'),
    80: ('HTTP', 'low'), 110: ('POP3', 'medium'), 143: ('IMAP', 'medium'),
    443: ('HTTPS', 'low'), 445: ('SMB', 'high'), 465: ('SMTPS', 'medium'),
    587: ('SMTP-TLS', 'medium'), 993: ('IMAPS', 'medium'), 995: ('POP3S', 'medium'),
    1080: ('SOCKS', 'high'), 1433: ('MSSQL', 'high'), 1521: ('Oracle', 'high'),
    2049: ('NFS', 'medium'), 2181: ('ZooKeeper', 'medium'), 2375: ('Docker', 'high'),
    3000: ('Node.js', 'low'), 3306: ('MySQL', 'high'), 3389: ('RDP', 'high'),
    5000: ('Flask/UPnP', 'medium'), 5432: ('PostgreSQL', 'high'), 5672: ('RabbitMQ', 'medium'),
    5900: ('VNC', 'high'), 5984: ('CouchDB', 'medium'), 6379: ('Redis', 'high'),
    6443: ('K8s-API', 'high'), 6666: ('Alt-HTTP', 'medium'), 7001: ('WebLogic', 'high'),
    8000: ('HTTP-Alt', 'low'), 8080: ('HTTP-Proxy', 'medium'), 8081: ('HTTP-Alt', 'low'),
    8443: ('HTTPS-Alt', 'medium'), 8888: ('HTTP-Alt', 'low'), 9000: ('PHP-FPM/Portainer', 'medium'),
    9090: ('Prometheus', 'medium'), 9092: ('Kafka', 'medium'), 9200: ('Elasticsearch', 'medium'),
    9300: ('ES-Transport', 'medium'), 9418: ('Git', 'low'), 11211: ('Memcached', 'high'),
    15672: ('RabbitMQ-Mgmt', 'medium'), 25565: ('Minecraft', 'low'),
    27017: ('MongoDB', 'high'), 50070: ('Hadoop', 'medium'),
    # 安全相关
    1337: ('Backdoor-Common', 'high'), 4444: ('Metasploit', 'high'),
    5555: ('ADB/Backdoor', 'high'), 6667: ('IRC', 'medium'),
    6668: ('IRC', 'medium'), 6669: ('IRC', 'medium'),
    8444: ('FRP-Common', 'high'), 29999: ('FRP-Dashboard', 'high'),
    10080: ('FRP-HTTP', 'high'), 10443: ('FRP-HTTPS', 'high'),
}


def classify_port(port, proto='tcp'):
    """根据端口号返回 (协议名称, 风险等级)"""
    if port in PORT_PROTOCOL_MAP:
        return PORT_PROTOCOL_MAP[port]
    if port < 1024:
        return ('系统端口', 'medium')
    if port < 49152:
        return ('注册端口', 'low')
    return ('动态端口', 'medium')


# TTL→操作系统推断
# 初始TTL: Linux=64, Windows=128, 网络设备/BSD=255
# 每经一跳路由TTL减1
OS_TTL_MAP = {
    # (lo, hi) → (操作系统, 置信度)
    (200, 255): ('网络设备/BSD', 'high'),      # TTL 200-255: 初始255
    (100, 128): ('Windows', 'high'),             # TTL 100-128: 初始128
    (33, 64): ('Linux/Unix/macOS', 'high'),      # TTL 33-64: 初始64
    (65, 99): ('Windows (经路由跳数减少)', 'medium'),  # TTL 65-99: 可能初始128
    (17, 32): ('Windows 95/旧系统 (或Linux经多跳)', 'low'),  # TTL 17-32
}

DEFAULT_OS_TTL = {
    'linux': 64, 'windows': 128, 'macos': 64, 'bsd': 255,
}


def guess_remote_os(ttl):
    """根据 TTL 推断对端操作系统"""
    if ttl is None:
        return '未知'
    for (lo, hi), (os_name, confidence) in OS_TTL_MAP.items():
        if lo <= ttl <= hi:
            return f'{os_name} (置信度:{confidence}, TTL={ttl})'
    if ttl < 17:
        return f'未知 (TTL={ttl}, 过低)'
    return f'未知 (TTL={ttl})'
