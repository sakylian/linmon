#!/usr/bin/env python3
"""
geo_locator.py — IP 归属地离线查询库 (IPv4 + IPv6)

兼容纯真 qqwry.dat (IPv4) 和 ZX ipv6wry.db (IPv6) 离线数据库格式，
灵感来自 nali (https://github.com/zu1k/nali) 的数据库方案。
支持中文位置标注，无需联网。

数据文件搜索路径（优先级从高到低）:
  1. 环境变量 CYBER_EYE_DATA_DIR 指定目录
  2. 脚本同级 ../data/ 目录
  3. ~/.local/share/cyber-eye/data/
  4. /usr/share/cyber-eye/data/
  5. 用户 linmon 项目 data/ 目录（兼容）
"""

import os
import sys
import struct
import socket
import ipaddress

# ──────────────────────── 路径解析 ────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_SCRIPT_DIR, '..', 'data')

def _build_candidate_dirs():
    """构建跨平台候选数据目录列表"""
    dirs = []
    # 1. 环境变量
    env_dir = os.environ.get('CYBER_EYE_DATA_DIR', '')
    if env_dir:
        dirs.append(env_dir)
    # 2. 脚本同级 ../data/
    dirs.append(_DATA_DIR)
    # 3. 平台通用数据目录
    if sys.platform == 'win32':
        dirs.append(os.path.join(os.environ.get('APPDATA', ''), 'cyber-eye', 'data'))
        dirs.append(os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 'cyber-eye', 'data'))
    elif sys.platform == 'darwin':
        dirs.append(os.path.expanduser('~/Library/Application Support/cyber-eye/data'))
    else:  # Linux/Unix
        dirs.append(os.path.expanduser('~/.local/share/cyber-eye/data'))
        dirs.append('/usr/share/cyber-eye/data')
    # 4. 兼容 linmon 项目（各平台通用）
    dirs.append(os.path.expanduser('~/下载/linmon/data'))
    dirs.append(os.path.expanduser('~/linmon/data'))
    return [d for d in dirs if d]


_CANDIDATE_DATA_DIRS = _build_candidate_dirs()


def _find_db(filename):
    """在候选目录中搜索数据库文件"""
    for d in _CANDIDATE_DATA_DIRS:
        if not d:
            continue
        p = os.path.join(d, filename)
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


def find_qqwry():
    return _find_db('qqwry.dat')


def find_ipv6wry():
    return _find_db('ipv6wry.db')


def find_cdn_yaml():
    return _find_db('cdn.yml')


# ──────────────────────── IPv4: 纯真库 ────────────────────────

class QqwryReader:
    """纯真 IPv4 离线数据库读取器"""

    def __init__(self, path):
        self.path = path
        self._fd = None
        self._loaded = False

    def load(self):
        self._fd = open(self.path, 'rb')
        buf = self._fd.read(8)
        self._first = struct.unpack('<I', buf[:4])[0]
        self._last = struct.unpack('<I', buf[4:8])[0]
        self._count = (self._last - self._first) // 7 + 1
        self._loaded = True

    def _rd_str(self, off):
        self._fd.seek(off)
        data = b''
        while True:
            ch = self._fd.read(1)
            if ch == b'\x00' or not ch:
                break
            data += ch
        return data.decode('gb18030', errors='replace')

    def _rd_area(self, off):
        self._fd.seek(off)
        b = self._fd.read(1)
        if b == b'\x01':
            ref = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
            return self._rd_str(ref) if ref else ''
        elif b == b'\x02':
            ref = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
            return self._rd_str(ref) if ref else ''
        else:
            return self._rd_str(off)

    def _rd_rec(self, off):
        self._fd.seek(off + 4)
        b = self._fd.read(1)
        if b == b'\x01':
            ref = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
            return self._rd_rec(ref)
        elif b == b'\x02':
            cref = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
            country = self._rd_str(cref)
            area = self._rd_area(off + 8)
            return country, area
        else:
            country = self._rd_str(off + 4)
            area = self._rd_area(self._fd.tell())
            return country, area

    def lookup(self, ip_str):
        if not self._loaded:
            return '', ''
        try:
            ip_int = struct.unpack('>I', socket.inet_aton(ip_str))[0]
        except (OSError, struct.error):
            return '', ''
        lo, hi = 0, self._count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            off = self._first + mid * 7
            self._fd.seek(off)
            mid_ip = struct.unpack('>I', self._fd.read(4))[0]
            if ip_int < mid_ip:
                hi = mid - 1
            elif ip_int > mid_ip:
                lo = mid + 1
            else:
                roff = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
                return self._rd_rec(roff)
        if hi < 0:
            return '', ''
        off = self._first + hi * 7
        self._fd.seek(off + 4)
        roff = struct.unpack('<I', self._fd.read(3) + b'\x00')[0]
        return self._rd_rec(roff)

    def close(self):
        if self._fd:
            self._fd.close()
            self._loaded = False


# ──────────────────────── IPv6: ZX 库 ────────────────────────

class Zxipv6wryReader:
    """ZX IPv6 离线数据库读取器 (ip.zxinc.org 格式)

    文件头(小端序): 魔数 'IPDB' + 版本 + offlen + iplen + 记录数 + 索引首偏移
    仅取 /64 前缀作为索引键
    """

    def __init__(self, path):
        self.path = path
        self._img = None
        self._loaded = False
        self._offlen = 3
        self._iplen = 8
        self._count = 0
        self._first = 0

    def _g8(self, off, size=8):
        s = self._img[off:off + size]
        if len(s) < 8:
            s += b'\x00' * (8 - len(s))
        return struct.unpack_from('<Q', s)[0]

    def load(self):
        with open(self.path, 'rb') as f:
            self._img = f.read()
        if self._img[:4] != b'IPDB':
            raise ValueError(f'IPv6 库格式错误: {self.path}')
        self._offlen = self._img[6]
        self._iplen = self._img[7]
        self._count = self._g8(8)
        self._first = self._g8(16)
        self._loaded = True

    def _g_str(self, off):
        if off < 0 or off >= len(self._img):
            return ''
        end = self._img.find(b'\x00', off)
        if end == -1:
            end = len(self._img)
        return self._img[off:end].decode('utf-8', errors='replace')

    def _g_area(self, off):
        if off < 0 or off >= len(self._img):
            return ''
        b = self._img[off]
        if b in (1, 2):
            return self._g_area(self._g8(off + 1, self._offlen))
        return self._g_str(off)

    def _g_addr(self, off):
        if off < 0 or off >= len(self._img):
            return '', ''
        b = self._img[off]
        if b == 1:
            return self._g_addr(self._g8(off + 1, self._offlen))
        country = self._g_area(off)
        if b == 2:
            o = off + 1 + self._offlen
        else:
            n = self._img.find(b'\x00', off)
            o = n + 1 if n != -1 else off + 1
        return country, self._g_area(o)

    def _find(self, prefix, lo, hi):
        if hi - lo <= 1:
            return lo
        mid = (lo + hi) // 2
        o = self._first + mid * (self._iplen + self._offlen)
        mid_ip = self._g8(o, self._iplen)
        if prefix < mid_ip:
            return self._find(prefix, lo, mid)
        return self._find(prefix, mid, hi)

    def lookup(self, ip_str):
        if not self._loaded:
            return '', ''
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except (ValueError, TypeError):
            return '', ''
        if ip_obj.version != 6:
            return '', ''
        prefix = (int(ip_obj) >> 64) & 0xFFFFFFFFFFFFFFFF
        if self._count == 0:
            return '', ''
        i = self._find(prefix, 0, self._count)
        off = self._first + i * (self._iplen + self._offlen)
        rec = self._g8(off + self._iplen, self._offlen)
        return self._g_addr(rec)

    def close(self):
        self._img = None
        self._loaded = False


# ──────────────────────── CDN 匹配 ────────────────────────

class CdnMatcher:
    """CDN 厂商域名匹配 (cdn.yml: domain -> info)，按后缀最长匹配"""

    _instance = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.load()
        return cls._instance

    def __init__(self):
        self._data = {}
        self._loaded = False

    def load(self, path=None):
        path = path or find_cdn_yaml()
        if not path or not os.path.isfile(path):
            return False
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            return False
        self._data = {str(k).lower(): v for k, v in data.items() if k}
        self._loaded = True
        return True

    def lookup(self, hostname):
        if not self._loaded or not hostname:
            return None
        h = hostname.lower().strip().rstrip('.')
        best = None
        for d in self._data:
            if h == d or h.endswith('.' + d):
                if best is None or len(d) > len(best):
                    best = d
        if not best:
            return None
        info = self._data[best]
        name = info.get('name', best) if isinstance(info, dict) else str(info)
        link = info.get('link', '') if isinstance(info, dict) else ''
        return {'provider': name, 'link': link}


# ──────────────────────── 坐标映射 ────────────────────────

GEO_COORDS = {
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
    '漳州': (117.647, 24.513), '泉州': (118.589, 24.908), '莆田': (119.007, 25.431),
    '宁德': (119.527, 26.659), '龙岩': (117.017, 25.075), '三明': (117.638, 26.263),
    '南平': (118.178, 26.642), '东莞': (113.751, 23.021), '佛山': (113.122, 23.029),
    '珠海': (113.552, 22.256), '中山': (113.393, 22.518), '惠州': (114.412, 23.079),
    '汕头': (116.682, 23.354), '湛江': (110.358, 21.270), '无锡': (120.312, 31.491),
    '南通': (120.865, 31.980), '徐州': (117.284, 34.206), '常州': (119.974, 31.812),
    '扬州': (119.421, 32.394), '温州': (120.699, 27.994), '宁波': (121.544, 29.868),
    '绍兴': (120.580, 30.030), '嘉兴': (120.755, 30.746), '金华': (119.647, 29.079),
    '台州': (121.421, 28.656), '烟台': (121.448, 37.464), '威海': (122.116, 37.509),
    '潍坊': (119.107, 36.709),
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

_PROVINCE_CAPS = {
    '福建': '福州', '广东': '广州', '浙江': '杭州', '江苏': '南京',
    '山东': '济南', '四川': '成都', '湖南': '长沙', '湖北': '武汉',
    '河南': '郑州', '河北': '石家庄', '安徽': '合肥', '江西': '南昌',
    '辽宁': '沈阳', '吉林': '长春', '黑龙江': '哈尔滨', '山西': '太原',
    '陕西': '西安', '甘肃': '兰州', '青海': '西宁', '云南': '昆明',
    '贵州': '贵阳', '广西': '南宁', '海南': '海口', '新疆': '乌鲁木齐',
    '内蒙古': '呼和浩特', '西藏': '拉萨', '宁夏': '银川',
}


def resolve_coordinates(geo_str):
    """将地理位置字符串解析为 (lng, lat) 坐标"""
    if not geo_str:
        return None, None
    for city, coords in GEO_COORDS.items():
        if city in geo_str:
            return coords
    for country, coords in COUNTRY_KEYWORDS.items():
        if country in geo_str:
            return coords
    for prov, cap in _PROVINCE_CAPS.items():
        if prov in geo_str and cap in GEO_COORDS:
            return GEO_COORDS[cap]
    return None, None


# ──────────────────────── IP 工具函数 ────────────────────────

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (ValueError, TypeError):
        return False


def is_valid_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                     or ip.is_multicast or ip.is_reserved)
    except (ValueError, TypeError):
        return False


def is_ipv6(ip_str):
    try:
        return ipaddress.ip_address(ip_str).version == 6
    except (ValueError, TypeError):
        return False


def _reverse_dns(ip_str, timeout=0.5):
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyaddr(ip_str)[0]
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        return ''


# ──────────────────────── 统一查询器 ────────────────────────

class GeoLocator:
    """统一的 IP 归属地查询器 (IPv4/IPv6 + CDN)"""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._init()
        return cls._instance

    def _init(self):
        self._v4 = None
        self._v6 = None
        self._v4_path = None
        self._v6_path = None

        p4 = find_qqwry()
        if p4:
            try:
                self._v4 = QqwryReader(p4)
                self._v4.load()
                self._v4_path = p4
            except Exception:
                self._v4 = None

        p6 = find_ipv6wry()
        if p6:
            try:
                self._v6 = Zxipv6wryReader(p6)
                self._v6.load()
                self._v6_path = p6
            except Exception:
                self._v6 = None

    @classmethod
    def lookup_ip(cls, ip_str, hostname=None, resolve_hostname=False):
        """查询 IP 归属地，返回 dict: ip, country, area, geo_str, lng, lat, cdn"""
        inst = cls.get_instance()
        country, area = '', ''
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            is_v6 = (ip_obj.version == 6)
        except (ValueError, TypeError):
            is_v6 = False

        if is_v6:
            if inst._v6:
                country, area = inst._v6.lookup(ip_str)
        else:
            if inst._v4:
                country, area = inst._v4.lookup(ip_str)

        geo_str = f'{country} {area}'.strip() if (country or area) else '未知'
        lng, lat = resolve_coordinates(geo_str)

        cdn = None
        if hostname is None and resolve_hostname and is_valid_public_ip(ip_str):
            hostname = _reverse_dns(ip_str)
        if hostname:
            cdn = CdnMatcher.get().lookup(hostname)

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
        return result

    @classmethod
    def db_status(cls):
        """返回数据库加载状态"""
        inst = cls.get_instance()
        return {
            'ipv4_db': inst._v4_path or '未找到',
            'ipv6_db': inst._v6_path or '未找到',
            'ipv4_loaded': inst._v4 is not None,
            'ipv6_loaded': inst._v6 is not None,
        }


# ──────────────────────── 端口风险映射 ────────────────────────

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
    1337: ('Backdoor-Common', 'high'), 4444: ('Metasploit', 'high'),
    5555: ('ADB/Backdoor', 'high'), 6667: ('IRC', 'medium'),
    6668: ('IRC', 'medium'), 6669: ('IRC', 'medium'),
    8444: ('FRP-Common', 'high'), 29999: ('FRP-Dashboard', 'high'),
    10080: ('FRP-HTTP', 'high'), 10443: ('FRP-HTTPS', 'high'),
}

HIGH_RISK_PORTS = {4444, 1337, 8444, 29999, 10080, 10443, 5555, 6666, 6667, 6668, 6669}


def classify_port(port):
    if port in PORT_PROTOCOL_MAP:
        return PORT_PROTOCOL_MAP[port]
    if port < 1024:
        return ('系统端口', 'medium')
    if port < 49152:
        return ('注册端口', 'low')
    return ('动态端口', 'medium')


def guess_remote_os(ttl):
    if ttl is None:
        return '未知'
    if 200 <= ttl <= 255:
        return f'网络设备/BSD (TTL={ttl})'
    if 100 <= ttl <= 128:
        return f'Windows (TTL={ttl})'
    if 33 <= ttl <= 64:
        return f'Linux/Unix/macOS (TTL={ttl})'
    if 65 <= ttl <= 99:
        return f'Windows (经路由跳转, TTL={ttl})'
    return f'未知 (TTL={ttl})'


# ──────────────────────── CLI ────────────────────────

def main():
    import sys, json, re
    if len(sys.argv) < 2:
        print("用法: python3 geo_locator.py <IP> [IP2 IP3 ...]")
        print("      echo '文本包含IP' | python3 geo_locator.py -p")
        status = GeoLocator.db_status()
        print(f"\n数据库状态: IPv4={status['ipv4_loaded']} ({status['ipv4_db']}), IPv6={status['ipv6_loaded']} ({status['ipv6_db']})")
        sys.exit(1)

    if sys.argv[1] == '-p' or sys.argv[1] == '--pipe':
        # 管道模式：从 stdin 读取文本，在 IP 后面附加归属地（类似 nali）
        text = sys.stdin.read()
        # 匹配 IPv4 和 IPv6
        pattern = re.compile(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'[\da-fA-F]{1,4}:[\da-fA-F:]+(?:\.\d{1,3}\.\d{1,3}\.\d{1,3})?)\b'
        )
        def replacer(m):
            ip = m.group(1)
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return ip
            if is_private_ip(ip):
                return f'{ip} [局域网]'
            result = GeoLocator.lookup_ip(ip)
            return f'{ip} [{result["geo_str"]}]'
        output = pattern.sub(replacer, text)
        print(output, end='')
    else:
        # 直接查询模式
        for ip_str in sys.argv[1:]:
            if is_private_ip(ip_str):
                print(f'{ip_str} [局域网]')
                continue
            result = GeoLocator.lookup_ip(ip_str)
            print(f'{ip_str} [{result["geo_str"]}]')


if __name__ == '__main__':
    main()
