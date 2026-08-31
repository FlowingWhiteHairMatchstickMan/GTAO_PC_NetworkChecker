import sys
import os
import socket
import struct
import threading
import time
import psutil
import requests
import ipaddress
import multiprocessing
import pydivert
import queue
import subprocess
import warnings
import shutil
from collections import deque, defaultdict

warnings.filterwarnings("ignore", category=DeprecationWarning)

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QLabel, QMessageBox, QHeaderView,
                             QTabWidget, QGroupBox, QFormLayout, QLineEdit,
                             QTextEdit, QComboBox, QDialog,
                             QDialogButtonBox, QCheckBox)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSettings
from PyQt6.QtGui import QColor, QBrush, QFont, QIcon

# ====================== ip2region 导入 ======================
try:
    import ip2region.util as util
    import ip2region.searcher as xdb
except ImportError:
    util = None
    xdb = None
    print("[警告] py-ip2region 库未安装，将仅使用在线API (pip install py-ip2region)")


def ensure_persistent_cache():
    if not getattr(sys, 'frozen', False):
        return

    exe_dir = os.path.dirname(sys.executable)
    cache_dir = os.path.join(exe_dir, "SessionManagerRuntime")
    if os.path.exists(cache_dir):
        needed = ["WinDivert.dll", "windivertctl.exe", "WinDivert64.sys"]
        if all(os.path.exists(os.path.join(cache_dir, f)) for f in needed):
            return

    if hasattr(sys, '_MEIPASS'):
        temp_dir = sys._MEIPASS
        os.makedirs(cache_dir, exist_ok=True)
        for f in ["WinDivert.dll", "windivertctl.exe", "WinDivert64.sys"]:
            src = os.path.join(temp_dir, f)
            dst = os.path.join(cache_dir, f)
            if os.path.exists(src):
                shutil.copy2(src, dst)
        print(f"[缓存] 已创建持久缓存: {cache_dir}")
# ====================== 路径辅助函数 ======================
def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

def get_resource_path(relative_path):
    """获取资源文件的绝对路径，兼容开发环境和 PyInstaller 打包"""
    if getattr(sys, 'frozen', False):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def get_icon_path():
    icon_filename = "ico.ico"

    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        icon_path = os.path.join(exe_dir, icon_filename)
        if os.path.exists(icon_path):
            return icon_path
        if hasattr(sys, '_MEIPASS'):
            icon_path = os.path.join(sys._MEIPASS, icon_filename)
            if os.path.exists(icon_path):
                return icon_path
        return icon_path
    else:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), icon_filename)


# ====================== DLL 搜索路径设置 ======================
def set_dll_search_path():
    import ctypes
    if sys.platform != "win32":
        return
    base_dir = get_base_path()
    cache_dir = os.path.join(base_dir, "SessionManagerRuntime")
    for d in [base_dir, cache_dir]:
        if os.path.exists(d):
            path_env = os.environ.get('PATH', '')
            if d not in path_env.split(os.pathsep):
                os.environ['PATH'] = d + os.pathsep + path_env
            if hasattr(os, 'add_dll_directory'):
                os.add_dll_directory(d)
            else:
                import ctypes
                ctypes.windll.kernel32.SetDllDirectoryW(d)
            dll_path = os.path.join(d, 'WinDivert.dll')
            if os.path.exists(dll_path):
                try:
                    ctypes.CDLL(dll_path)
                    print(f"[DLL] 已从 {d} 加载")
                except:
                    pass


# ====================== ip2region ======================
HAS_IP2REGION = False
ip2region_searcher = None
IP2REGION_DB_PATH = get_resource_path("ip2region.xdb")
IP_VERSION = util.IPv4 if util else None

def init_ip2region():
    """加载 ip2region 官方库，若失败则标记为不可用"""
    global HAS_IP2REGION, ip2region_searcher
    if util is None or xdb is None:
        print("[ip2region] 依赖库未安装，跳过本地查询")
        return
    if not os.path.exists(IP2REGION_DB_PATH):
        print(f"[ip2region] 未找到数据库文件: {IP2REGION_DB_PATH}，将使用在线API")
        return
    try:
        util.verify_from_file(IP2REGION_DB_PATH)
        ip2region_searcher = xdb.new_with_file_only(IP_VERSION, IP2REGION_DB_PATH)
        HAS_IP2REGION = True
        print("[ip2region] 官方库初始化成功")
    except Exception as e:
        print(f"[ip2region] 初始化失败: {e}，将使用在线API")
        ip2region_searcher = None
        HAS_IP2REGION = False


# ====================== WinDivert 驱动安装 ======================
def ensure_windivert_driver():
    if sys.platform != "win32":
        return True
    if check_driver_available():
        print("[驱动] 驱动已就绪")
        return True
    try:
        if not pydivert.WinDivert.is_registered():
            pydivert.WinDivert.register()
        if check_driver_available():
            return True
    except:
        pass

    try:
        base = get_base_path()
        ctl_path = os.path.join(base, "windivertctl.exe")
        if not os.path.exists(ctl_path):
            print("[驱动] windivertctl.exe 未找到")
            return False
        subprocess.run([ctl_path, "uninstall"], capture_output=True, timeout=5)
        time.sleep(0.5)
        subprocess.run([ctl_path, "install"], capture_output=True, timeout=10)
        subprocess.run(["sc", "start", "windivert"], capture_output=True, timeout=5)
        time.sleep(2)
        return check_driver_available()
    except:
        return False

def check_driver_available():
    try:
        w = pydivert.WinDivert("false")
        w.open()
        w.close()
        return True
    except Exception as e:
        return False


# ====================== 配置常量 ======================
SAMPLE_INTERVAL = 2
UI_REFRESH_RATE = 10
HISTORY_SIZE = 10
GEO_CACHE_TTL = 3600

UDP_PORTS_TO_MONITOR = {6672, 61455, 61456, 61457, 61458}
TARGET_PROCESS_KEYWORDS = ["GTA5", "GTA5_Enhanced", "RDR2"]

TRADE_SERVER_IPS = {"192.81.245.200", "192.81.245.201"}
CLOUD_SAVE_SERVER_IPS = {"192.81.241.171","192.81.241.191"}
ROCKSTAR_DOMAINS = {
    "conductor-prod.ros.rockstargames.com",
    "patches.rockstargames.com",
    "prod.cloud.rockstargames.com",
    "prod.cs.ros.rockstargames.com",
    "prod.ros.rockstargames.com",
    "prod.telemetry.ros.rockstargames.com"
}
ROCKSTAR_IP_RANGES = ["52.139."]

# ====================== 辅助 函数 ======================
geo_cache = {}
dns_cache = {}
data_lock = threading.Lock()
geo_lock = threading.Lock()
dns_lock = threading.Lock()


def get_str_width(s):
    width = 0
    for char in s:
        width += 2 if '\u4e00' <= char <= '\u9fff' else 1
    return width


def truncate_mixed_string(text, max_width):
    current_width = 0
    result = ""
    for char in text:
        char_width = 2 if '\u4e00' <= char <= '\u9fff' else 1
        if current_width + char_width > max_width:
            return result + ".."
        result += char
        current_width += char_width
    return result


def pad_text(text, width, align='left'):
    text = str(text)
    w = get_str_width(text)
    if w > width:
        return truncate_mixed_string(text, width - 2)
    if align == 'left':
        return text + " " * (width - w)
    elif align == 'right':
        return " " * (width - w) + text
    else:
        left = (width - w) // 2
        right = width - w - left
        return " " * left + text + " " * right


def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except:
        return False


def reverse_dns_lookup(ip):
    with dns_lock:
        if ip in dns_cache:
            return dns_cache[ip]
    try:
        domain = socket.gethostbyaddr(ip)[0]
        with dns_lock:
            dns_cache[ip] = domain
        return domain
    except:
        return None


def get_rockstar_server_type(ip, domain, asn_info=None):
    if ip in TRADE_SERVER_IPS:
        return "官方-交易服务器"
    elif ip in CLOUD_SAVE_SERVER_IPS:
        return "官方-云存档服务器"
    if domain:
        domain_lower = domain.lower()
        for rd in ROCKSTAR_DOMAINS:
            if rd in domain_lower:
                return "官方-CDN服务器与云服务器"
        if "rockstargames.com" in domain_lower or "take-two" in domain_lower:
            return "官方-其他服务器"
    if any(ip.startswith(r) for r in ROCKSTAR_IP_RANGES):
        return "官方-中转服务器"
    if asn_info and ("take-two" in asn_info.lower() or "take two" in asn_info.lower()):
        return "官方-其他服务器"
    return None


def parse_asn_info(asn_str):
    if not asn_str:
        return None, None
    parts = asn_str.split(' ', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, asn_str


def get_friendly_isp_name(isp_data, org_data, as_data):
    as_number, as_name = parse_asn_info(as_data)
    if as_number and as_name:
        simplified = as_name
        for kw, short in [("Tencent", "腾讯"), ("Alibaba", "阿里云"), ("China Telecom", "电信"),
                          ("China Mobile", "移动"), ("China Unicom", "联通"), ("Cloudflare", "Cloudflare"),
                          ("Google", "谷歌"), ("Microsoft", "微软"), ("Amazon", "AWS"), ("AWS", "AWS"),
                          ("Take-Two", "Take-Two"), ("Netease", "网易云")]:
            if kw in as_name:
                simplified = short
                break
        return f"{as_number} ({simplified})"
    if org_data:
        org_lower = org_data.lower()
        for kw, short in [("tencent", "腾讯"), ("alibaba", "阿里云"), ("china telecom", "电信"),
                          ("china mobile", "移动"), ("china unicom", "联通"), ("take-two", "Take-Two"),
                          ("cloudflare", "Cloudflare"), ("google", "谷歌"), ("microsoft", "微软"),
                          ("amazon", "亚马逊"), ("aws", "亚马逊"), ("netease", "网易云")]:
            if kw in org_lower:
                return short
        return truncate_mixed_string(org_data, 25)
    return truncate_mixed_string(isp_data, 25) if isp_data else "未知"


# ====================== 地理地区检测 ======================
def decode_ip2region_bytes(data):
    """尝试多种编码解码 ip2region 返回的字节数据"""
    encodings = ['gb18030', 'gbk', 'gb2312', 'big5', 'utf-8', 'latin-1']
    for enc in encodings:
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode('utf-8', errors='replace')
def get_geo_info(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    if not is_public_ip(ip):
        info = ("区域网", "-", False, None, False)
        geo_cache[ip] = info
        return info

    # ---------- 备用：ip2region 地区 & ISP ----------
    ip2_location = None
    ip2_is_chinese = False
    ip2_isp = None

    if ip2region_searcher is not None:
        try:
            region_raw = ip2region_searcher.search(ip)
            if region_raw:
                if isinstance(region_raw, bytes):
                    region_str = decode_ip2region_bytes(region_raw)
                else:
                    region_str = region_raw
                parts = region_str.split('|')
                while len(parts) < 5:
                    parts.append('')
                country = parts[0].strip()
                area = parts[1].strip() if len(parts) > 1 else ""
                province = parts[2].strip() if len(parts) > 2 else ""
                city = parts[3].strip() if len(parts) > 3 else ""
                isp = parts[4].strip() if len(parts) > 4 else ""

                def clean(s):
                    return s if s and s not in ("0", "0.0", "未知") else ""
                country = clean(country); area = clean(area)
                province = clean(province); city = clean(city); isp = clean(isp)

                non_mainland = ["香港", "澳门", "台湾", "Hong Kong", "Macau", "Taiwan"]
                is_hk_mo_tw = any(kw in (area + province + city) or kw in country for kw in non_mainland)
                ip2_is_chinese = (country in ("中国", "China")) and not is_hk_mo_tw

                if country in ("中国", "China"):
                    if province and city:
                        if city.startswith(province) or province.startswith(city):
                            location = province
                        else:
                            location = f"{province}{city}"
                    elif province:
                        location = province
                    elif area:
                        location = area
                    elif country:
                        location = country
                    else:
                        location = "未知"
                else:
                    loc_parts = [country] if country else []
                    if province and province != country:
                        loc_parts.append(province)
                    if city and city not in (country, province):
                        loc_parts.append(city)
                    location = " ".join(loc_parts[:2]) if loc_parts else "未知"
                if location:
                    ip2_location = location
                if isp:
                    ip2_isp = isp
        except Exception as e:
            print(f"[ip2region] 查询 {ip} 失败: {e}")

    # ---------- 优先：API 完整查询----------
    api_success = False
    api_country = api_region = api_city = api_isp = api_org = api_as = api_domain = ""

    max_retries = 5
    retry_delay = 1

    for attempt in range(max_retries):
        try:
            url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp,org,as"
            r = requests.get(url, timeout=8)
            if r.status_code == 200:
                d = r.json()
                if d.get('status') == 'success':
                    api_success = True
                    api_country = d.get('country', '')
                    api_region = d.get('regionName', '')
                    api_city = d.get('city', '')
                    api_isp = d.get('isp', '')
                    api_org = d.get('org', '')
                    api_as = d.get('as', '')
                    api_domain = reverse_dns_lookup(ip)
                    break
        except Exception:
            pass
        if attempt < max_retries - 1:
            time.sleep(retry_delay)

    # ---------- 组合地区 ----------
    using_fallback = False
    api_has_region = bool(api_success and (api_country or api_region or api_city))
    if api_has_region:
        if api_country == '中国':
            location = f"{api_region}{api_city}" if api_city else (api_region or api_country)
        else:
            loc_parts = []
            if api_country:
                loc_parts.append(api_country)
            if api_region and api_region != api_city:
                loc_parts.append(api_region)
            if api_city:
                loc_parts.append(api_city)
            location = " ".join(loc_parts[:2]) if loc_parts else api_country
        if not location.strip():
            location = "未知"
        non_mainland = ["香港", "澳门", "台湾", "Hong Kong", "Macau", "Taiwan"]
        is_hk_mo_tw = any(kw in (api_region + api_city) or kw in api_country for kw in non_mainland)
        is_chinese = (api_country == '中国') and not is_hk_mo_tw
    else:
        location = ip2_location if ip2_location else "未知"
        is_chinese = ip2_is_chinese
        using_fallback = True

    # ---------- ISP 与服务器类型 ----------
    if api_success and (api_isp or api_org or api_as):
        friendly_isp = get_friendly_isp_name(api_isp, api_org, api_as)
        isp = friendly_isp
        server_type = get_rockstar_server_type(ip, api_domain, api_as or api_org)
    else:
        isp = ip2_isp if ip2_isp else "未知"
        domain = reverse_dns_lookup(ip) if not api_domain else api_domain
        server_type = get_rockstar_server_type(ip, domain, ip2_isp)

    info = (location, isp, is_chinese, server_type, using_fallback)
    geo_cache[ip] = info
    return info


# ====================== Peer 类 ======================
class Peer:
    def __init__(self, ip):
        self.ip = ip
        self.location = "查询中..."
        self.isp = "-"
        self.is_chinese = False
        self.server_type = None
        self.using_fallback = False
        self.last_total_bytes = 0
        self.last_seen = time.time()
        self.history = deque(maxlen=HISTORY_SIZE)
        threading.Thread(target=self._fetch_geo, daemon=True).start()

    def _fetch_geo(self):
        if not is_public_ip(self.ip):
            self.location = "区域网"
            self.isp = "-"
            self.is_chinese = False
            self.server_type = None
            self.using_fallback = False
            return
        location, isp, is_chinese, server_type, using_fallback = get_geo_info(self.ip)
        self.location = location
        self.isp = isp
        self.is_chinese = is_chinese
        self.server_type = server_type
        self.using_fallback = using_fallback

    def record_sample(self, current_total_bytes):
        delta = current_total_bytes - self.last_total_bytes
        if delta < 0:
            delta = 0
        self.last_total_bytes = current_total_bytes
        if delta > 0:
            self.last_seen = time.time()
        speed = (delta / SAMPLE_INTERVAL) / 1024.0
        self.history.append((speed, None))

    def get_summary(self):
        if not self.history:
            return None
        speeds = [x[0] for x in self.history]
        avg_speed = sum(speeds) / len(speeds)
        max_speed = max(speeds)
        time_since_seen = time.time() - self.last_seen
        is_alive = time_since_seen < (SAMPLE_INTERVAL * HISTORY_SIZE * 1.5)
        is_lagger = avg_speed > 100 or max_speed > 100
        return {
            'avg_speed': avg_speed,
            'max_speed': max_speed,
            'is_alive': is_alive,
            'last_seen_sec': int(time_since_seen),
            'is_lagger': is_lagger
        }


# ====================== 全局抓包变量 ======================
raw_bytes_map = defaultdict(int)
peers_map = {}
gta_ports = set(UDP_PORTS_TO_MONITOR)
running = True
LOCAL_IP = ""


def sniffer():
    global raw_bytes_map, gta_ports, running
    if ":" in LOCAL_IP:
        local_ip, _ = LOCAL_IP.split(":")
    else:
        local_ip = LOCAL_IP
    local_ips = set()
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                local_ips.add(addr.address)
    if local_ip and local_ip not in local_ips:
        local_ips.add(local_ip)
    print(f"[嗅探器] 绑定到 IP: {local_ip}")
    print(f"[嗅探器] 本地IP列表: {list(local_ips)}")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.bind((local_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if hasattr(socket, 'SIO_RCVALL') and psutil.WINDOWS:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print(f"[嗅探器] 成功绑定到 {local_ip}")
    except Exception as e:
        print(f"嗅探器初始化失败: {e}，请以管理员权限运行")
        return

    while running:
        try:
            raw = s.recvfrom(65535)[0]
            iph = struct.unpack('!BBHHHBBH4s4s', raw[0:20])
            if iph[6] != 17:
                continue
            ihl = (iph[0] & 0xF) * 4
            udph = struct.unpack('!HHHH', raw[ihl:ihl + 8])
            src_port = udph[0]
            dst_port = udph[1]
            if not (src_port in gta_ports or dst_port in gta_ports):
                continue
            s_ip = socket.inet_ntoa(iph[8])
            d_ip = socket.inet_ntoa(iph[9])

            if s_ip in local_ips:
                remote = d_ip
            elif d_ip in local_ips:
                remote = s_ip
            else:
                continue

            if remote.startswith(("224.", "239.", "255.")) or remote in local_ips:
                continue

            with data_lock:
                raw_bytes_map[remote] += len(raw)
        except:
            pass


def sampler():
    global peers_map, raw_bytes_map, running
    while running:
        time.sleep(SAMPLE_INTERVAL)
        with data_lock:
            current_ips = list(raw_bytes_map.keys())
        for ip in current_ips:
            if ip not in peers_map:
                peers_map[ip] = Peer(ip)
        for ip, peer in list(peers_map.items()):
            with data_lock:
                current_total = raw_bytes_map.get(ip, 0)
            peer.record_sample(current_total)
            stats = peer.get_summary()
            if stats and not stats['is_alive']:
                with data_lock:
                    if ip in peers_map:
                        del peers_map[ip]
                    if ip in raw_bytes_map:
                        del raw_bytes_map[ip]


def port_scanner():
    global gta_ports, running
    while running:
        tmp = set()
        try:
            for p in psutil.process_iter(['name']):
                try:
                    if p.info['name'] and any(x in p.info['name'] for x in TARGET_PROCESS_KEYWORDS):
                        connections = p.net_connections(kind='udp')
                        for conn in connections:
                            if conn.laddr:
                                port = conn.laddr.port
                                if port in UDP_PORTS_TO_MONITOR:
                                    tmp.add(port)
                except:
                    pass
        except:
            pass
        all_ports = UDP_PORTS_TO_MONITOR.union(tmp)
        if all_ports != gta_ports:
            gta_ports = all_ports
        time.sleep(5)


# ====================== 过滤器函数 ======================
def run_solo_filter():
    set_dll_search_path()
    try:
        import pydivert
        filter_str = "(udp.DstPort == 6672 and udp.PayloadLength > 0) and ip"
        solo_filter = pydivert.WinDivert(filter_str)
        solo_filter.open()
    except Exception as e:
        print(f"卡单人战局过滤器启动失败: {e}")
        return
    heartbeat_sizes = {12, 18, 63}
    while True:
        try:
            packet = solo_filter.recv(100)
            if packet is None:
                continue
            size = len(packet.payload)
            if size in heartbeat_sizes:
                solo_filter.send(packet)
                continue
            wrapper = 0
            magic = 0
            if size >= 5:
                wrapper = int.from_bytes(packet.raw[28:30], 'big')
                magic = int.from_bytes([packet.payload[4], packet.payload[4]], 'big')
            if size == wrapper:
                offset = packet.payload[2] ^ packet.payload[4]
                code = 0
                alt = 0
                if offset == 17 and size >= 27:
                    code = int.from_bytes(packet.payload[25:27], 'big')
                    alt = packet.payload[24]
                elif offset == 49 and size >= 91:
                    code = int.from_bytes(packet.payload[89:91], 'big')
                dtls = {0xfeff, 0xfefd}
                if code ^ magic in dtls:
                    solo_filter.send(packet)
                    continue
                if alt ^ packet.payload[4] in {0x39, 0x31, 0x29}:
                    solo_filter.send(packet)
                    continue
                if code ^ magic < 0x10:
                    solo_filter.send(packet)
                    continue
        except Exception:
            pass


def run_locked_filter(counter, msg_queue):
    set_dll_search_path()
    try:
        import pydivert
        filter_str = "udp.DstPort == 6672 and udp.PayloadLength > 0 and ip"
        w = pydivert.WinDivert(filter_str)
        w.open()
        print("战局锁已启动（锁定模式）")
        matchmaking_sizes = {191, 207, 223, 239}
        while True:
            packet = w.recv()
            if packet is None:
                continue
            size = len(packet.payload)
            if size in matchmaking_sizes:
                with counter.get_lock():
                    counter.value += 1
                if packet.is_inbound:
                    blocked_ip = packet.src_addr
                else:
                    blocked_ip = packet.dst_addr
                server_type = get_rockstar_server_type(blocked_ip, None, None)
                try:
                    msg_queue.put((blocked_ip, server_type), timeout=0.1)
                except queue.Full:
                    pass
                continue
            w.send(packet)
    except Exception as e:
        print(f"战局锁过滤器启动失败: {e}")

def run_endpoint_lock_filter(whitelist, msg_queue):
    set_dll_search_path()
    try:
        import pydivert
        filter_str = "(udp.DstPort == 6672 and udp.PayloadLength > 0) and ip"
        w = pydivert.WinDivert(filter_str)
        w.open()
        print("战局锁已启动（端点白名单模式）")
        heartbeat_sizes = {12, 18, 63}
        while True:
            packet = w.recv()
            if packet is None:
                continue
            if not packet.is_inbound:
                w.send(packet)
                continue
            size = len(packet.payload)
            if size in heartbeat_sizes:
                w.send(packet)
                continue
            endpoint = (packet.src_addr, packet.src_port)
            if endpoint in whitelist:
                w.send(packet)
            else:
                ip = packet.src_addr
                server_type = get_rockstar_server_type(ip, None, None)
                if server_type == "官方-中转服务器":
                    try:
                        msg_queue.put((ip, server_type), timeout=0.1)
                    except queue.Full:
                        pass
                continue
    except Exception as e:
        print(f"战局锁过滤器启动失败: {e}")

def blocker_process_func(local_ip, cmd_queue):
    set_dll_search_path()
    import pydivert
    import time
    import queue

    port_list = ' or '.join(f'udp.DstPort == {p}' for p in UDP_PORTS_TO_MONITOR)
    filter_str = f"({port_list}) and ip"
    w = None
    try:
        w = pydivert.WinDivert(filter_str)
        w.open()
        print("[阻断进程] 过滤器已启动")
    except Exception as e:
        print(f"[阻断进程] 启动失败: {e}")
        return

    blocked_ips = set()
    temp_blocked = {}

    while True:
        try:
            cmd = cmd_queue.get_nowait()
            if cmd is None:
                break
            if cmd[0] == 'block':
                _, ip, permanent, duration_sec = cmd
                if permanent:
                    blocked_ips.add(ip)
                    print(f"[阻断进程] 永久阻断: {ip}")
                else:
                    temp_blocked[ip] = time.time() + duration_sec
                    print(f"[阻断进程] 临时阻断: {ip} ({duration_sec}s)")
            elif cmd[0] == 'unblock':
                _, ip = cmd
                if ip in blocked_ips:
                    blocked_ips.discard(ip)
                    print(f"[阻断进程] 解除永久: {ip}")
                if ip in temp_blocked:
                    del temp_blocked[ip]
                    print(f"[阻断进程] 解除临时: {ip}")
        except queue.Empty:
            pass

        now = time.time()
        for ip in list(temp_blocked.keys()):
            if now >= temp_blocked[ip]:
                del temp_blocked[ip]
                print(f"[阻断进程] 临时超时解除: {ip}")

        try:
            packet = w.recv()
            if packet is None:
                continue
            if not packet.is_inbound:
                w.send(packet)
                continue
            src_ip = packet.src_addr
            if local_ip and src_ip == local_ip:
                w.send(packet)
                continue
            if src_ip in blocked_ips or src_ip in temp_blocked:
                continue
            else:
                w.send(packet)
        except Exception as e:
            print(f"[阻断进程] 异常: {e}")
            break

    if w:
        w.close()
    print("[阻断进程] 退出")


# ====================== 按需阻断管理器 ======================
class OnDemandBlocker:
    def __init__(self):
        self.blocked_ips = set()
        self.temp_blocked = {}
        self.process = None
        self.cmd_queue = None
        self.running = False
        self.local_ip = None
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        self._check_thread = None
        self._check_running = False

    def set_local_ip(self, ip):
        self.local_ip = ip

    def check_driver(self):
        try:
            w = pydivert.WinDivert("false")
            w.open()
            w.close()
            return True
        except Exception as e:
            print(f"[阻断] 驱动检查失败: {e}")
            return False

    def _start_internal(self):
        if self.running:
            return
        if not self.check_driver():
            print("[阻断] WinDivert 驱动不可用，阻断功能将无效")
            return

        self._stop_event.clear()
        self.cmd_queue = multiprocessing.Queue()
        self.process = multiprocessing.Process(
            target=blocker_process_func,
            args=(self.local_ip, self.cmd_queue),
            daemon=True
        )
        self.process.start()
        self.running = True
        self._start_check_thread()
        print("[阻断] 阻断进程已按需启动")

    def _start_check_thread(self):
        if self._check_running:
            return
        self._check_running = True
        self._check_thread = threading.Thread(target=self._check_temp_blocked, daemon=True)
        self._check_thread.start()

    def _check_temp_blocked(self):
        while self._check_running and self.running:
            time.sleep(1)
            now = time.time()
            expired_ips = []
            with self.lock:
                for ip, expire_time in list(self.temp_blocked.items()):
                    if now >= expire_time:
                        expired_ips.append(ip)
            for ip in expired_ips:
                print(f"[阻断] 临时阻断已超时，自动解除: {ip}")
                self.unblock_ip(ip)

    def _stop_check_thread(self):
        self._check_running = False
        if self._check_thread and self._check_thread.is_alive():
            try:
                self._check_thread.join(0.1)
            except RuntimeError:
                pass
        self._check_thread = None

    def _stop_internal(self, timeout=0.5):
        if not self.running:
            return

        self.running = False
        self._stop_event.set()

        if self.cmd_queue:
            try:
                self.cmd_queue.put(None, timeout=0.1)
            except:
                pass

        if self.process and self.process.is_alive():
            def wait_for_process():
                try:
                    self.process.join(timeout)
                    if self.process.is_alive():
                        self.process.terminate()
                        self.process.join(0.3)
                except Exception as e:
                    print(f"[阻断] 停止进程时出错: {e}")
                finally:
                    self.process = None
                    self.cmd_queue = None
                    self._stop_check_thread()
                    print("[阻断] 阻断进程已停止")

            threading.Thread(target=wait_for_process, daemon=True).start()
        else:
            self.process = None
            self.cmd_queue = None
            self._stop_check_thread()
            print("[阻断] 阻断进程已停止")

    def block_ip(self, ip, permanent=True, duration_sec=30):
        if not self.check_driver():
            print("[阻断] 驱动不可用，无法阻断")
            return False
        if self.local_ip and ip == self.local_ip:
            print(f"[阻断] 拒绝阻断本机 IP {ip}")
            return False

        if not self.running:
            self._start_internal()
            if not self.running:
                print("[阻断] 阻断进程启动失败")
                return False

        try:
            self.cmd_queue.put(('block', ip, permanent, duration_sec), timeout=0.5)
            with self.lock:
                if permanent:
                    self.blocked_ips.add(ip)
                else:
                    self.temp_blocked[ip] = time.time() + duration_sec
            print(f"[阻断] 已添加阻断: {ip} ({'永久' if permanent else '临时'})")
            return True
        except queue.Full:
            print("[阻断] 命令队列已满")
            return False

    def unblock_ip(self, ip):
        if self.running:
            try:
                self.cmd_queue.put(('unblock', ip), timeout=0.5)
            except:
                pass

        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips.discard(ip)
                print(f"[阻断] 已解除永久阻断: {ip}")
            if ip in self.temp_blocked:
                del self.temp_blocked[ip]
                print(f"[阻断] 已解除临时阻断: {ip}")

        if self.running and not self.blocked_ips and not self.temp_blocked:
            self._stop_internal()

    def kick_ip(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            kick_packet = bytearray()
            kick_packet.extend(b'\x00' * 4)
            kick_packet.extend(b'\x01\x00\x00\x00')
            kick_packet.extend(struct.pack('!I', 0xFFFFFFFF))
            kick_packet.extend(b'\x00' * 20)
            sock.sendto(kick_packet, (ip, 6672))
            time.sleep(0.05)
            sock.sendto(kick_packet, (ip, 6672))
            sock.close()
            print(f"[踢人] 已发送踢人包到 {ip}")
            return True
        except Exception as e:
            print(f"[踢人] 失败: {e}")
            return False

    def is_blocked(self, ip):
        with self.lock:
            if ip in self.blocked_ips:
                return True, "永久"
            if ip in self.temp_blocked:
                remaining = int(self.temp_blocked[ip] - time.time())
                return True, f"临时({remaining}s)"
            return False, ""

    def get_blocked(self):
        now = time.time()
        with self.lock:
            result = {}
            for ip in self.blocked_ips:
                result[ip] = -1
            for ip, t in self.temp_blocked.items():
                remaining = max(0, int(t - now))
                result[ip] = remaining
            return result

    def stop(self):
        with self.lock:
            self._stop_check_thread()
            self._stop_internal()
            self.blocked_ips.clear()
            self.temp_blocked.clear()


# ====================== 进程监控线程 ======================
class ProcessMonitorThread(QThread):
    process_exited = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.running = True
        self.ip_first_seen = {}
        self.enabled = False

    def update_ips(self, peers):
        if not self.enabled:
            return
        now = time.time()
        for ip in peers.keys():
            if ip not in self.ip_first_seen:
                self.ip_first_seen[ip] = now

    def set_enabled(self, enabled):
        self.enabled = enabled
        if not enabled:
            self.ip_first_seen.clear()

    def run(self):
        last_alive = True
        while self.running:
            process_exists = False
            for proc in psutil.process_iter(['name']):
                try:
                    name = proc.info['name']
                    if name and any(kw in name for kw in TARGET_PROCESS_KEYWORDS):
                        process_exists = True
                        break
                except:
                    pass
            if not process_exists and last_alive:
                if self.enabled:
                    now = time.time()
                    recent_ips = [ip for ip, ts in self.ip_first_seen.items() if now - ts <= 3]
                    if recent_ips:
                        self.process_exited.emit(recent_ips)
                last_alive = False
            elif process_exists:
                last_alive = True
            time.sleep(1)

    def stop(self):
        self.running = False


# ====================== 加速器检测线程 ======================
class AcceleratorTestThread(QThread):
    output = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, phy_ip, virt_ip):
        super().__init__()
        self.phy_ip = phy_ip
        self.virt_ip = virt_ip
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        w = None
        try:
            import pydivert
            self.output.emit("=" * 70)
            self.output.emit("开始加速器有效性检测")
            self.output.emit(f"物理网卡IP: {self.phy_ip}")
            self.output.emit(f"虚拟网卡IP: {self.virt_ip}")
            self.output.emit("=" * 70)
            self.output.emit("请确保游戏处于在线战局并有其他玩家...")
            self.output.emit("检测将持续10秒...")

            phy_packets = set()
            virt_packets = set()
            official_ips = TRADE_SERVER_IPS | CLOUD_SAVE_SERVER_IPS

            port_list = ' or '.join(f'(udp.SrcPort == {p} or udp.DstPort == {p})' for p in UDP_PORTS_TO_MONITOR)
            filter_str = f"({port_list}) and ip"

            self.output.emit("正在启动网络过滤器...")
            w = pydivert.WinDivert(filter_str)
            w.open()
            self.output.emit("过滤器已启动，开始捕获数据包...")

            start_time = time.time()
            packet_count = 0
            timeout_count = 0

            while self.running and (time.time() - start_time) < 10:
                try:
                    packet = w.recv(100)
                    if packet is None:
                        timeout_count += 1
                        if timeout_count % 10 == 0:
                            self.output.emit(f"等待数据包... (已等待 {int(time.time() - start_time)} 秒)")
                        continue
                    timeout_count = 0

                    packet_count += 1
                    if packet_count % 5 == 0:
                        self.output.emit(f"已捕获 {packet_count} 个数据包...")

                    if packet.udp is None:
                        w.send(packet)
                        continue

                    src_ip = packet.src_addr
                    dst_ip = packet.dst_addr

                    if src_ip == self.phy_ip or src_ip == self.virt_ip:
                        remote = dst_ip
                    else:
                        remote = src_ip

                    if remote in official_ips:
                        w.send(packet)
                        continue

                    is_rockstar = False
                    for r in ROCKSTAR_IP_RANGES:
                        if remote.startswith(r):
                            is_rockstar = True
                            break
                    if is_rockstar:
                        w.send(packet)
                        continue

                    if remote.startswith(('224.', '239.', '255.', '127.', '0.')):
                        w.send(packet)
                        continue

                    if src_ip == self.phy_ip or dst_ip == self.phy_ip:
                        phy_packets.add(remote)
                    if src_ip == self.virt_ip or dst_ip == self.virt_ip:
                        virt_packets.add(remote)

                    w.send(packet)

                except Exception as e:
                    if "timeout" in str(e).lower():
                        continue
                    else:
                        self.output.emit(f"处理数据包时出错: {e}")
                        break

            self.output.emit("")
            self.output.emit("=" * 70)
            self.output.emit("检测结果")
            self.output.emit("=" * 70)
            self.output.emit(f"物理网卡({self.phy_ip}) 检测到 {len(phy_packets)} 个P2P连接")
            self.output.emit(f"虚拟网卡({self.virt_ip}) 检测到 {len(virt_packets)} 个P2P连接")
            self.output.emit(f"总共捕获 {packet_count} 个数据包")
            self.output.emit("")

            if packet_count == 0:
                self.output.emit("⚠️ 警告: 未捕获到任何数据包")
                self.output.emit("可能原因:")
                self.output.emit("  - 游戏未进入在线战局")
                self.output.emit("  - 战局无其他玩家")
                self.output.emit("  - IP地址配置错误")
                self.output.emit("  - 杀毒软件/防火墙阻止了WinDivert")
            elif len(virt_packets) == 0 and len(phy_packets) == 0:
                self.output.emit("⚠️ 警告: 两个网卡均未检测到P2P游戏连接")
                self.output.emit("可能原因: 游戏未进入在线战局 / 战局无其他玩家 / IP地址错误")
            elif len(virt_packets) > 0 and len(phy_packets) > 0:
                self.output.emit("⚠️ 注意：加速器加速可能已失效")
                self.output.emit("P2P连接同时出现在物理网卡和虚拟网卡上")
                if len(virt_packets) > len(phy_packets) * 2:
                    self.output.emit("流量分析: 虚拟网卡流量占优 → 加速器部分工作")
                elif len(phy_packets) > len(virt_packets) * 2:
                    self.output.emit("流量分析: 物理网卡流量占优 → 大部分流量未经过加速器")
                else:
                    self.output.emit("流量分析: 两个网卡流量相当 → 流量严重分流")
                self.output.emit("建议：重启加速器并更换节点，或使用进程模式")
            elif len(virt_packets) > len(phy_packets) * 3:
                self.output.emit("✅ 加速器状态: 正常加速")
            elif len(phy_packets) > len(virt_packets) * 3:
                self.output.emit("⚠️⚠️⚠️ 加速器状态: 可能为假加速 ⚠️⚠️⚠️")
                self.output.emit("建议：更换加速器或联系客服")

            self.output.emit("")
            self.output.emit("=" * 70)

        except Exception as e:
            self.output.emit(f"检测出错: {e}")
            import traceback
            self.output.emit(traceback.format_exc())
        finally:
            if w:
                try:
                    w.close()
                except:
                    pass
            self.finished_signal.emit()


# ====================== 战局管理器 ======================
class SessionManager:
    def __init__(self):
        self.solo_process = None
        self.locked_process = None
        self.solo_running = False
        self.locked_running = False
        self.locked_counter = None
        self.locked_msg_queue = None

    def start_solo_session(self):
        if self.solo_running:
            return False, "卡单人战局已在运行中"
        if self.locked_running:
            return False, "请先关闭战局锁"
        self.solo_running = True
        self.solo_process = multiprocessing.Process(target=run_solo_filter, daemon=True)
        self.solo_process.start()
        return True, "卡单人战局已启动"

    def stop_solo_session(self):
        if not self.solo_running:
            return False, "卡单人战局未运行"
        self.solo_running = False
        if self.solo_process and self.solo_process.is_alive():
            self.solo_process.terminate()
            self.solo_process.join(0.5)
        return True, "卡单人战局已停止"

    def start_locked_session(self):
        if self.locked_running:
            return False, "战局锁已在运行中"
        if self.solo_running:
            return False, "请先关闭卡单人战局"
        self.locked_running = True
        self.locked_counter = multiprocessing.Value('i', 0)
        self.locked_msg_queue = multiprocessing.Queue()
        self.locked_process = multiprocessing.Process(
            target=run_locked_filter,
            args=(self.locked_counter, self.locked_msg_queue),
            daemon=True
        )
        self.locked_process.start()
        return True, "握手包战局锁已启动"

    def stop_locked_session(self):
        if not self.locked_running:
            return False, "战局锁未运行"
        self.locked_running = False
        if self.locked_process and self.locked_process.is_alive():
            self.locked_process.terminate()
            self.locked_process.join(0.5)
        self.locked_counter = None
        return True, "战局锁已停止"

    def stop_all(self):
        """停止所有正在运行的战局管理进程"""
        if self.solo_running:
            self.stop_solo_session()
        if self.locked_running:
            self.stop_locked_session()


class SessionControlTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.session_manager = SessionManager()
        self.lock_count_timer = QTimer()
        self.lock_count_timer.timeout.connect(self.update_lock_count)

        # ---------- 方式二相关 ----------
        self.current_mode = None
        self.collector_running = False
        self.collector_thread = None
        self.endpoint_last_seen = {}
        self.endpoint_lock = threading.Lock()
        self.filter_process_v2 = None
        self.msg_queue_v2 = None
        self.start_v2_thread = None
        self.blocked_count_v2 = 0
        self.start_collecting()
        # -----------------------------

        self.setup_ui()

    # ==================== 采集方法 ====================
    def start_collecting(self):
        """启动后台采集线程（无感知）"""
        if self.collector_running:
            return
        self.collector_running = True
        self.collector_thread = threading.Thread(target=self._collector_loop, daemon=True)
        self.collector_thread.start()

    def stop_collecting(self):
        """停止采集线程"""
        self.collector_running = False
        if self.collector_thread and self.collector_thread.is_alive():
            self.collector_thread.join(timeout=1)

    def _collector_loop(self):
        try:
            with pydivert.WinDivert("(udp.DstPort == 6672 and udp.PayloadLength > 0) and ip") as w:
                while self.collector_running:
                    try:
                        packet = w.recv()
                        w.send(packet)
                        if packet.is_inbound:
                            endpoint = (packet.src_addr, packet.src_port)
                            with self.endpoint_lock:
                                self.endpoint_last_seen[endpoint] = time.time()
                    except Exception:
                        continue
        except Exception as e:
            print(f"[采集] 异常: {e}")

    # ==================== UI 布局 ====================
    def setup_ui(self):
        layout = QVBoxLayout(self)

        self.status_group = QGroupBox("当前状态")
        status_layout = QFormLayout(self.status_group)
        self.solo_status_label = QLabel("未启动")
        self.locked_status_label = QLabel("未启动")
        self.locked_block_count_label = QLabel("0")
        status_layout.addRow("卡单人战局:", self.solo_status_label)
        status_layout.addRow("战局锁:", self.locked_status_label)
        status_layout.addRow("已阻止的网络包个数:", self.locked_block_count_label)
        layout.addWidget(self.status_group)

        btn_group = QGroupBox("控制面板")
        btn_layout = QHBoxLayout(btn_group)
        self.solo_start_btn = QPushButton("启动卡单人战局")
        self.solo_start_btn.clicked.connect(self.start_solo_session)
        self.solo_stop_btn = QPushButton("停止卡单人战局")
        self.solo_stop_btn.clicked.connect(self.stop_solo_session)
        self.locked_start_btn = QPushButton("启动握手包战局锁")
        self.locked_start_btn.clicked.connect(self.start_locked_session)
        self.locked_start_btn_v2 = QPushButton("启动端点白名单战局锁")
        self.locked_start_btn_v2.clicked.connect(self.start_locked_session_v2)
        self.locked_stop_btn = QPushButton("停止战局锁")
        self.locked_stop_btn.clicked.connect(self.stop_locked_session)

        btn_layout.addWidget(self.solo_start_btn)
        btn_layout.addWidget(self.solo_stop_btn)
        btn_layout.addWidget(self.locked_start_btn)
        btn_layout.addWidget(self.locked_start_btn_v2)
        btn_layout.addWidget(self.locked_stop_btn)
        layout.addWidget(btn_group)

        log_group = QGroupBox("操作日志")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        layout.addWidget(log_group)

        tip_label = QLabel(
            "使用建议：\n1. 先进入邀请战局。\n2. 邀请您的好友全部进入战局。\n3. 启动战局锁，此时新玩家与外挂玩家无法追入战局，但已连接的玩家不受影响。")
        tip_label.setWordWrap(True)
        font = tip_label.font()
        font.setPointSize(12)
        tip_label.setFont(font)
        tip_label.setStyleSheet("color: gray;")
        layout.addWidget(tip_label)

    # ==================== 卡单人战局 ====================
    def start_solo_session(self):
        success, msg = self.session_manager.start_solo_session()
        if success:
            self.solo_status_label.setText("运行中")
            self.solo_status_label.setStyleSheet("color: green;")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 卡单人战局已启动")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

    def stop_solo_session(self):
        success, msg = self.session_manager.stop_solo_session()
        if success:
            self.solo_status_label.setText("未启动")
            self.solo_status_label.setStyleSheet("")  # 恢复默认颜色
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 卡单人战局已停止")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

    # ==================== 战局锁方式一 ====================
    def start_locked_session(self):
        if self.current_mode == 'v2':
            self.stop_locked_session()
        success, msg = self.session_manager.start_locked_session()
        if success:
            self.current_mode = 'v1'
            self.locked_status_label.setText("运行中")
            self.locked_status_label.setStyleSheet("color: green;")
            self.locked_block_count_label.setText("0")
            self.lock_count_timer.start(50)
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 握手包战局锁已启动")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

    # ==================== 战局锁方式二（异步启动） ====================
    class StartV2Thread(QThread):
        finished = pyqtSignal(bool, str)

        def __init__(self, parent_tab):
            super().__init__()
            self.parent_tab = parent_tab

        def run(self):
            try:
                self.parent_tab.stop_collecting()
                now = time.time()
                whitelist = set()
                with self.parent_tab.endpoint_lock:
                    for endpoint, last_seen in self.parent_tab.endpoint_last_seen.items():
                        if now - last_seen <= 5:
                            whitelist.add(endpoint)
                msg_queue = multiprocessing.Queue()
                proc = multiprocessing.Process(
                    target=run_endpoint_lock_filter,
                    args=(whitelist, msg_queue),
                    daemon=True
                )
                proc.start()
                if not whitelist:
                    msg = "白名单为空，可能导致其他玩家全部掉线"
                else:
                    msg = f"端点白名单生成，共 {len(whitelist)} 个端点"

                self.parent_tab.filter_process_v2 = proc
                self.parent_tab.msg_queue_v2 = msg_queue
                self.parent_tab.current_mode = 'v2'
                self.parent_tab.blocked_count_v2 = 0
                self.finished.emit(True, msg)
            except Exception as e:
                self.finished.emit(False, f"启动失败: {e}")

    def start_locked_session_v2(self):
        if self.session_manager.solo_running:
            self.session_manager.stop_solo_session()
            self.solo_status_label.setText("未启动")
            self.solo_status_label.setStyleSheet("")  # 恢复默认颜色
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 卡单人战局已自动停止")
        if self.current_mode == 'v1':
            self.stop_locked_session()
        if self.current_mode == 'v2':
            QMessageBox.warning(self, "警告", "端点白名单战局锁已在运行中")
            return
        self.locked_start_btn_v2.setEnabled(False)
        self.locked_start_btn_v2.setText("启动中...")
        self.start_v2_thread = self.StartV2Thread(self)
        self.start_v2_thread.finished.connect(self._on_start_v2_finished)
        self.start_v2_thread.start()

    def _on_start_v2_finished(self, success, msg):
        self.locked_start_btn_v2.setEnabled(True)
        self.locked_start_btn_v2.setText("启动端点白名单战局锁")

        if success:
            self.locked_status_label.setText("运行中")
            self.locked_status_label.setStyleSheet("color: green;")
            self.locked_block_count_label.setText("0")  # 初始为0
            self.lock_count_timer.start(50)
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 端点白名单战局锁已启动")
            if "白名单为空" in msg:
                self.log_text.append(f"[{time.strftime('%H:%M:%S')}] [警告] {msg}")
            else:
                self.log_text.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
            QMessageBox.information(self, "成功", "端点白名单战局锁已启动")
        else:
            self.current_mode = None
            if not self.collector_running:
                self.start_collecting()
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 端点白名单战局锁启动失败: {msg}")
            QMessageBox.critical(self, "错误", f"启动失败: {msg}")

        self.start_v2_thread = None

    # ==================== 停止战局锁（统一） ====================
    def stop_locked_session(self):
        if self.current_mode is None:
            QMessageBox.warning(self, "警告", "当前没有运行中的战局锁")
            return

        if self.current_mode == 'v1':
            success, msg = self.session_manager.stop_locked_session()
            if success:
                self.locked_status_label.setText("未启动")
                self.locked_status_label.setStyleSheet("")
                self.lock_count_timer.stop()
                self.locked_block_count_label.setText("-")
                self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 握手包战局锁已停止")
                QMessageBox.information(self, "成功", msg)
            else:
                QMessageBox.warning(self, "警告", msg)
                return
        elif self.current_mode == 'v2':
            if self.filter_process_v2 and self.filter_process_v2.is_alive():
                self.filter_process_v2.terminate()
                self.filter_process_v2.join(0.5)
            self.filter_process_v2 = None
            self.msg_queue_v2 = None
            self.blocked_count_v2 = 0
            self.locked_status_label.setText("未启动")
            self.locked_status_label.setStyleSheet("")
            self.lock_count_timer.stop()
            self.locked_block_count_label.setText("-")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 端点白名单战局锁已停止")
            QMessageBox.information(self, "成功", "端点白名单战局锁已停止")

        self.current_mode = None
        if not self.collector_running:
            self.start_collecting()

    # ==================== 定时更新阻止计数 ====================
    def update_lock_count(self):
        if self.current_mode is None:
            self.lock_count_timer.stop()
            self.locked_block_count_label.setText("-")
            return

        if self.current_mode == 'v1':
            counter = self.session_manager.locked_counter
            if counter is not None:
                current = counter.value
                self.locked_block_count_label.setText(str(current))
            msg_queue = self.session_manager.locked_msg_queue
            if msg_queue:
                count = 0
                while count < 100:
                    try:
                        item = msg_queue.get_nowait()
                        ip, server_type = item
                        timestamp = time.strftime('%H:%M:%S')
                        if server_type == "官方-中转服务器":
                            self.log_text.append(f"[{timestamp}] 已阻止此IP疑似加入请求：{ip} [中转]")
                        else:
                            self.log_text.append(f"[{timestamp}] 已阻止此IP疑似加入请求：{ip}")
                        count += 1
                    except queue.Empty:
                        break

        elif self.current_mode == 'v2':
            msg_queue = self.msg_queue_v2
            if msg_queue:
                count = 0
                while count < 100:
                    try:
                        item = msg_queue.get_nowait()
                        ip, server_type = item
                        timestamp = time.strftime('%H:%M:%S')
                        if server_type == "官方-中转服务器":
                            self.log_text.append(f"[{timestamp}] 已阻止此IP连接：{ip} [中转]")
                        else:
                            self.log_text.append(f"[{timestamp}] 已阻止此IP连接：{ip}")
                        self.blocked_count_v2 += 1
                        count += 1
                    except queue.Empty:
                        break
            self.locked_block_count_label.setText(str(self.blocked_count_v2))

# ====================== 主窗口 ======================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GTA 在线模式 & Red Dead 在线模式 战局管理工具")
        self.resize(1100, 650)
        self.driver_available = check_driver_available()
        if not self.driver_available:
            print("[主程序] 驱动不可用，尝试安装...")
            self.driver_available = ensure_windivert_driver()
            if not self.driver_available:
                QMessageBox.warning(self, "WinDivert 驱动不可用",
                                    "WinDivert 驱动加载失败！\n\n"
                                    "以下功能将被禁用：\n"
                                    "• 阻断连接（临时阻断、黑名单）\n"
                                    "• 战局管理（卡单人战局、战局锁）\n"
                                    "• 加速器检测\n\n"
                                    "请尝试以下解决方法：\n"
                                    "1. 以管理员身份重新运行本程序\n"
                                    "2. 检查杀毒软件是否阻止了 WinDivert 驱动\n"
                                    "3. 手动安装 WinDivert 驱动：\n"
                                    "   https://github.com/basil00/Divert/releases")
            else:
                QMessageBox.information(self, "驱动安装成功",
                                        "WinDivert 驱动已成功安装！\n\n"
                                        "所有功能现在可用。")
        global LOCAL_IP
        LOCAL_IP = self.get_user_input_ip()
        if not LOCAL_IP:
            QMessageBox.critical(self, "错误", "未选择有效IP，程序退出")
            sys.exit(1)
        self.base_path = get_base_path()
        self.blacklist_file = os.path.join(self.base_path, "permanent_blacklist.txt")
        self.permanent_blacklist = set()
        self.load_blacklist()
        init_ip2region()
        threading.Thread(target=sniffer, daemon=True).start()
        threading.Thread(target=sampler, daemon=True).start()
        threading.Thread(target=port_scanner, daemon=True).start()
        self.blocker = OnDemandBlocker()
        self.blocker.set_local_ip(LOCAL_IP)
        if self.driver_available and self.permanent_blacklist:
            for ip in self.permanent_blacklist:
                self.blocker.block_ip(ip, permanent=True)
        elif not self.driver_available:
            print("[主程序] 驱动不可用，阻断器未启动")
        self.proc_monitor = ProcessMonitorThread()
        self.proc_monitor.process_exited.connect(self.on_process_exited)
        self.proc_monitor.start()
        self.setup_ui()
        if not self.driver_available:
            self.disable_windivert_features()
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_display)
        self.refresh_timer.start(UI_REFRESH_RATE * 1000)
        self.block_timer = QTimer()
        self.block_timer.timeout.connect(self.update_block_table)
        self.block_timer.start(1000)
        self.crash_detection_enabled = False
        self.show_private_ip = False
        self.show()

    # ====================== 通用工具函数 ======================
    def get_text_dialog(self, title, label, placeholder="", parent=None):
        dialog = QDialog(parent or self)
        dialog.setWindowTitle(title)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        input_label = QLabel(label)
        layout.addWidget(input_label)

        input_edit = QLineEdit()
        input_edit.setPlaceholderText(placeholder)
        layout.addWidget(input_edit)

        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("确定")
        cancel_btn = QPushButton("取消")

        ok_btn.clicked.connect(dialog.accept)
        cancel_btn.clicked.connect(dialog.reject)

        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

        ok_btn.setDefault(True)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            return input_edit.text().strip()
        return None

    def show_question_dialog(self, title, text, default_no=True):
        yes_btn = QPushButton("是")
        no_btn = QPushButton("否")

        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(text)
        msg_box.setIcon(QMessageBox.Icon.Question)
        msg_box.addButton(yes_btn, QMessageBox.ButtonRole.YesRole)
        msg_box.addButton(no_btn, QMessageBox.ButtonRole.NoRole)
        msg_box.setDefaultButton(no_btn if default_no else yes_btn)

        msg_box.exec()
        return msg_box.clickedButton() == yes_btn

    def disable_windivert_features(self):
        # ==================== 禁用战局管理相关 ====================
        self.session_tab.solo_start_btn.setEnabled(False)
        self.session_tab.solo_stop_btn.setEnabled(False)
        self.session_tab.locked_start_btn.setEnabled(False)
        self.session_tab.locked_stop_btn.setEnabled(False)

        self.session_tab.solo_start_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.solo_stop_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.locked_start_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.locked_stop_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")

        self.session_tab.solo_start_btn.setStyleSheet("QPushButton { color: gray; }")
        self.session_tab.solo_stop_btn.setStyleSheet("QPushButton { color: gray; }")
        self.session_tab.locked_start_btn.setStyleSheet("QPushButton { color: gray; }")
        self.session_tab.locked_stop_btn.setStyleSheet("QPushButton { color: gray; }")

        self.session_tab.solo_status_label.setText("❌ 不可用")
        self.session_tab.solo_status_label.setStyleSheet("color: gray;")
        self.session_tab.locked_status_label.setText("❌ 不可用")
        self.session_tab.locked_status_label.setStyleSheet("color: gray;")

        self.session_tab.log_text.append("⚠️ WinDivert 驱动不可用，战局管理功能已禁用")

        # ==================== 禁用阻断连接相关 ====================
        self.temp_block_btn.setEnabled(False)
        self.temp_block_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.temp_block_btn.setStyleSheet("QPushButton { color: gray; }")

        self.blacklist_enabled.setEnabled(False)
        self.blacklist_enabled.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.blacklist_enabled.setStyleSheet("QCheckBox { color: gray; }")

        if hasattr(self, 'add_bl_btn'):
            self.add_bl_btn.setEnabled(False)
            self.add_bl_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
            self.add_bl_btn.setStyleSheet("QPushButton { color: gray; }")

        if hasattr(self, 'remove_bl_btn'):
            self.remove_bl_btn.setEnabled(False)
            self.remove_bl_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
            self.remove_bl_btn.setStyleSheet("QPushButton { color: gray; }")

        self.block_table.setRowCount(1)
        self.block_table.setItem(0, 0, QTableWidgetItem("⚠ 驱动不可用"))
        self.block_table.setItem(0, 1, QTableWidgetItem("功能已禁用"))
        self.block_table.setItem(0, 2, QTableWidgetItem(""))
        self.block_table.item(0, 0).setForeground(QBrush(QColor(255, 100, 100)))

        # ==================== 禁用加速器检测 ====================
        self.detect_btn.setEnabled(False)
        self.detect_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.detect_btn.setStyleSheet("QPushButton { color: gray; }")

        self.acc_output.setPlainText(
            "⚠️ WinDivert 驱动不可用\n\n加速器检测功能已禁用。\n\n请以管理员身份重新运行程序，\n或检查杀毒软件是否阻止了 WinDivert 驱动。")

        # ==================== 状态栏提示 ====================
        self.driver_status_label = QLabel("⚠ WinDivert 驱动不可用，部分功能已禁用")
        self.driver_status_label.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 2px 10px;")
        self.statusBar().addPermanentWidget(self.driver_status_label)

    def on_fix_windivert(self):
        reply = QMessageBox.question(
            self,
            "确认修复",
            "此操作将删除 WinDivert 驱动并重启程序。\n"
            "重启后驱动会自动重新安装。\n\n"
            "确定继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            result = subprocess.run(
                ["sc", "delete", "WinDivert"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            if result.returncode == 0:
                QMessageBox.information(self, "成功", "WinDivert 驱动已删除，程序即将重启...")
            else:
                QMessageBox.warning(
                    self,
                    "警告",
                    f"删除驱动失败（可能驱动未安装）：{result.stderr}\n程序仍将重启尝试修复。"
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "错误",
                f"执行命令出错：{e}\n程序仍将重启尝试修复。"
            )
        self.cleanup_resources()
        self.restart_program()

    def on_temp_block_ip(self):
        if not self.driver_available:
            QMessageBox.warning(self, "功能不可用",
                                "WinDivert 驱动不可用，无法使用临时阻断功能。\n\n"
                                "请以管理员身份重新运行程序。")
            return

        ip = self.get_text_dialog("临时阻断IP", "请输入要临时阻断的IP地址（30秒后自动解除）：", "例如: 114.114.114.114")
        if ip is None:
            return
        try:
            socket.inet_aton(ip)
            self.blocker.block_ip(ip, permanent=False, duration_sec=30)
            self.update_block_table()
            QMessageBox.information(self, "成功", f"已临时阻断IP {ip}，30秒后将自动解除")
        except socket.error:
            QMessageBox.warning(self, "错误", "无效的IP地址格式")
    def get_user_input_ip(self):
        config_file = os.path.join(get_base_path(), "config.ini")
        base_dir = get_base_path()
        try:
            test_file = os.path.join(base_dir, ".write_test")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            can_write = True
        except:
            can_write = False
            print(f"[警告] 程序目录不可写: {base_dir}")
            import tempfile
            config_file = os.path.join(tempfile.gettempdir(), "gtanetmonitor_config.ini")
            print(f"[配置] 改用临时目录: {config_file}")
        settings = QSettings(config_file, QSettings.Format.IniFormat)
        remember = settings.value("RememberIP", "false")
        if isinstance(remember, bool):
            remember = remember
        elif isinstance(remember, str):
            remember = remember.lower() in ("true", "1", "yes")
        else:
            remember = False
        last_ip = settings.value("LastSelectedIP", "", type=str)
        # ============ 获取所有本地IP并测试可绑定性 ============
        bindable_ips = []
        nic_info = {}
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    ip = addr.address
                    is_bindable = self.test_ip_bindable(ip)
                    nic_info[ip] = {
                        'name': name,
                        'bindable': is_bindable
                    }
                    if is_bindable:
                        bindable_ips.append(ip)
                    status = "可绑定" if is_bindable else "不可绑定"
                    print(f"[网络] 网卡 {name}: {ip} {status}")
        if not bindable_ips:
            QMessageBox.critical(self, "错误",
                                 "未找到可绑定的IP地址！\n\n"
                                 "请确保至少有一个网卡处于活动状态。\n"
                                 "程序将退出。")
            sys.exit(1)
        if remember and last_ip and last_ip in bindable_ips:
            print(f"[配置] 使用上次选择的 IP: {last_ip}")
            return last_ip
        if len(bindable_ips) == 1:
            selected_ip = bindable_ips[0]
            print(f"[配置] 自动选择唯一可绑定IP: {selected_ip}")
            settings.setValue("LastSelectedIP", selected_ip)
            settings.setValue("RememberIP", remember)
            settings.sync()
            return selected_ip

        # ============ 多个可绑定IP时，弹窗让用户选择 ============
        dialog = QDialog(self)
        dialog.setWindowTitle("选择监控IP")
        dialog.setModal(True)
        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        dialog.setWindowFlags(dialog.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        dialog.setMinimumWidth(480)
        font = dialog.font()
        font.setPointSize(10)
        dialog.setFont(font)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(10)
        # ============ 提示文字 ============
        tip_label = QLabel(
            "请选择你要监控的IP地址\n\n"
            "路由模式加速 → 请选择加速器的虚拟网卡IP\n"
            "裸连或进程模式加速 → 请选择实际联网的网卡IP\n\n"
            "提示：192.168.x.x 通常是家庭网络，172.x.x.x 通常是虚拟网卡"
        )
        tip_label.setWordWrap(True)
        tip_label.setFont(font)
        tip_label.setStyleSheet("padding: 5px;")
        layout.addWidget(tip_label)
        # ============ IP选择下拉框 ============
        label = QLabel("可用IP地址：")
        label.setFont(font)
        layout.addWidget(label)
        combo = QComboBox()
        combo.setFont(font)
        combo.setMinimumHeight(30)
        for ip in sorted(bindable_ips):
            info = nic_info.get(ip, {})
            name = info.get('name', '未知网卡')
            combo.addItem(f"{name}: {ip}", ip)
        if combo.count() == 0:
            combo.addItem("无可用IP", "")
        if last_ip and last_ip in bindable_ips:
            idx = combo.findData(last_ip)
            if idx >= 0:
                combo.setCurrentIndex(idx)
        layout.addWidget(combo)
        remember_checkbox = QCheckBox("记住我的选择")
        remember_checkbox.setFont(font)
        remember_checkbox.setChecked(remember)
        layout.addWidget(remember_checkbox)
        # ============ 按钮 ============
        ok_btn = QPushButton("确定")
        cancel_btn = QPushButton("取消")
        btn_box = QDialogButtonBox()
        btn_box.addButton(ok_btn, QDialogButtonBox.ButtonRole.AcceptRole)
        btn_box.addButton(cancel_btn, QDialogButtonBox.ButtonRole.RejectRole)
        btn_box.setFont(font)
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected_ip = combo.currentData()
            if not selected_ip:
                QMessageBox.critical(self, "错误", "未选择有效IP，程序退出")
                sys.exit(1)
            settings.setValue("LastSelectedIP", selected_ip)
            settings.setValue("RememberIP", remember_checkbox.isChecked())
            settings.sync()
            print(f"[配置] 保存 IP: {selected_ip}")
            return selected_ip
        else:
            QMessageBox.critical(self, "错误", "未选择有效IP，程序退出")
            sys.exit(1)
    def test_ip_bindable(self, ip):
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            test_sock.bind((ip, 0))
            test_sock.close()
            return True
        except Exception as e:
            print(f"[测试] IP {ip} 不可绑定: {e}")
            return False
    def save_blacklist(self):
        with open(self.blacklist_file, 'w') as f:
            for ip in self.permanent_blacklist:
                f.write(f"{ip}\n")
    def load_blacklist(self):
        try:
            with open(self.blacklist_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.permanent_blacklist.add(ip)
        except FileNotFoundError:
            pass
    def restart_program(self):
        QTimer.singleShot(500, self._really_restart)
    def _really_restart(self):
        os.execl(sys.executable, sys.executable, *sys.argv)
    def setup_ui(self):
        self.tabs = QTabWidget()
        self.monitor_tab = QWidget()
        self.acc_tab = QWidget()
        self.session_tab = SessionControlTab(self)
        layout = QVBoxLayout(self.monitor_tab)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        layout.addWidget(self.console)
        btn_layout = QHBoxLayout()
        self.crash_btn = QPushButton("挂逼崩溃战局检测")
        self.crash_btn.setCheckable(True)
        self.crash_btn.toggled.connect(self.on_crash_detection_toggled)
        self.refresh_geo_btn = QPushButton("重试未知地理位置")
        self.refresh_geo_btn.clicked.connect(self.on_refresh_geo)
        btn_layout.addWidget(self.crash_btn)
        btn_layout.addWidget(self.refresh_geo_btn)
        self.forget_ip_btn = QPushButton("忘记记住的IP")
        self.forget_ip_btn.clicked.connect(self.on_forget_ip)
        btn_layout.addWidget(self.forget_ip_btn)
        tip = QLabel("卡逼判定规则：IP定位位置在国内或距离您物理位置过远，连接比其他玩家速率过大，或对方网络环境未启用upnp被游戏转入中转服务器连接。")
        tip.setStyleSheet("color: gray;")
        layout.addWidget(tip)
        self.tabs.addTab(self.monitor_tab, "战局IP检测")
        self.setup_accelerator_tab()
        self.tabs.addTab(self.acc_tab, "路由模式加速器检测")
        self.tabs.addTab(self.session_tab, "网络战局锁")
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.addWidget(self.tabs)
        main_layout.addWidget(left_widget, 3)
        right_widget = self.create_right_panel()
        main_layout.addWidget(right_widget, 2)
        self.status_label = QLabel(
            f"监控IP: {LOCAL_IP} | 端口: {sorted(UDP_PORTS_TO_MONITOR)} | 临时阻断: 0 | 永久黑名单: {len(self.permanent_blacklist)}")
        self.statusBar().addWidget(self.status_label)
    def create_right_panel(self):
        right_widget = QWidget()
        right_widget.setMaximumWidth(350)
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(5, 5, 5, 5)
        right_layout.setSpacing(10)
        block_group = QGroupBox("阻断连接")
        block_layout = QVBoxLayout(block_group)
        self.block_table = QTableWidget()
        self.block_table.setColumnCount(3)
        self.block_table.setHorizontalHeaderLabels(["IP地址", "状态", "操作"])
        self.block_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        block_layout.addWidget(self.block_table)
        temp_block_btn_layout = QHBoxLayout()
        self.temp_block_btn = QPushButton("添加IP临时阻断")
        self.temp_block_btn.clicked.connect(self.on_temp_block_ip)
        temp_block_btn_layout.addWidget(self.temp_block_btn)
        block_layout.addLayout(temp_block_btn_layout)
        right_layout.addWidget(block_group)
        blacklist_group = QGroupBox("黑名单设置")
        blacklist_layout = QVBoxLayout(blacklist_group)
        self.blacklist_enabled = QCheckBox("启用黑名单")
        self.blacklist_enabled.setChecked(False)
        self.blacklist_enabled.toggled.connect(self.on_blacklist_toggled)
        blacklist_layout.addWidget(self.blacklist_enabled)
        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(2)
        self.blacklist_table.setHorizontalHeaderLabels(["IP地址", "操作"])
        self.blacklist_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.refresh_blacklist_table()
        blacklist_layout.addWidget(self.blacklist_table)
        bl_btn_layout = QHBoxLayout()
        self.add_bl_btn = QPushButton("添加IP到黑名单")
        self.add_bl_btn.clicked.connect(self.on_add_to_blacklist)
        self.remove_bl_btn = QPushButton("从黑名单移除")
        self.remove_bl_btn.clicked.connect(self.on_remove_from_blacklist)
        bl_btn_layout.addWidget(self.add_bl_btn)
        bl_btn_layout.addWidget(self.remove_bl_btn)
        blacklist_layout.addLayout(bl_btn_layout)
        right_layout.addWidget(blacklist_group)
        forget_group = QGroupBox("软件设置")
        forget_layout = QVBoxLayout(forget_group)
        self.forget_ip_setting_btn = QPushButton("忘记记住的IP地址")
        self.forget_ip_setting_btn.clicked.connect(self.on_forget_ip)
        forget_layout.addWidget(self.forget_ip_setting_btn)
        forget_tip = QLabel("点击后将清除已记住的IP地址，下次启动将重新选择")
        forget_tip.setStyleSheet("color: gray; font-size: 9px;")
        forget_layout.addWidget(forget_tip)
        self.fix_windivert_btn = QPushButton("尝试修复WinDivert驱动")
        self.fix_windivert_btn.clicked.connect(self.on_fix_windivert)
        if self.driver_available:
            self.fix_windivert_btn.setEnabled(False)
            self.fix_windivert_btn.setToolTip("驱动已正常，无需修复")
        else:
            self.fix_windivert_btn.setEnabled(True)
            self.fix_windivert_btn.setToolTip("点击删除损坏的驱动并重启程序以重新安装")
        forget_layout.addWidget(self.fix_windivert_btn)
        fix_tip = QLabel("重置当前WinDivert驱动，按下确定后将会进行清理并自动重启程序")
        fix_tip.setStyleSheet("color: gray; font-size: 9px;")
        forget_layout.addWidget(fix_tip)
        right_layout.addWidget(forget_group)
        return right_widget
    def setup_accelerator_tab(self):
        layout = QVBoxLayout(self.acc_tab)
        tip_label = QLabel("注意：此检测功能仅适用于\"路由模式\"的加速器。\n"
                           "如果您使用进程模式加速，将无法检测。")
        tip_label.setWordWrap(True)
        tip_label.setStyleSheet("color: orange; background-color: #FFF3CD; border: 1px solid #FFEEBA; padding: 5px;")
        layout.addWidget(tip_label)
        info_group = QGroupBox("当前网络接口信息")
        info_layout = QVBoxLayout(info_group)
        self.nic_table = QTableWidget()
        self.nic_table.setColumnCount(3)
        self.nic_table.setHorizontalHeaderLabels(["接口名称", "IP地址", "类型"])
        self.nic_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        info_layout.addWidget(self.nic_table)
        refresh_nic_btn = QPushButton("刷新网卡信息")
        refresh_nic_btn.clicked.connect(self.refresh_nic_table)
        info_layout.addWidget(refresh_nic_btn)
        layout.addWidget(info_group)

        input_group = QGroupBox("IP地址配置")
        input_layout = QFormLayout(input_group)
        self.phy_ip_edit = QLineEdit()
        self.phy_ip_edit.setPlaceholderText("例如: 192.168.1.100")
        self.virt_ip_edit = QLineEdit()
        self.virt_ip_edit.setPlaceholderText("例如: 172.20.10.1")
        input_layout.addRow("物理网卡IP:", self.phy_ip_edit)
        input_layout.addRow("虚拟网卡IP:", self.virt_ip_edit)
        layout.addWidget(input_group)
        output_group = QGroupBox("检测输出")
        output_layout = QVBoxLayout(output_group)
        self.acc_output = QTextEdit()
        self.acc_output.setReadOnly(True)
        self.acc_output.setFont(QFont("Consolas", 9))
        output_layout.addWidget(self.acc_output)
        layout.addWidget(output_group)
        self.detect_btn = QPushButton("开始检测加速器")
        self.detect_btn.setMinimumHeight(40)
        self.detect_btn.clicked.connect(self.on_detect_accelerator)
        layout.addWidget(self.detect_btn)
    def refresh_nic_table(self):
        self.nic_table.setRowCount(0)
        row = 0
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    self.nic_table.insertRow(row)
                    self.nic_table.setItem(row, 0, QTableWidgetItem(name))
                    self.nic_table.setItem(row, 1, QTableWidgetItem(addr.address))
                    name_lower = name.lower()
                    if any(kw in name_lower for kw in ["virtual", "vpn", "tap", "vmnet"]):
                        type_str = "虚拟网卡"
                    elif any(kw in name_lower for kw in ["wireless", "wifi", "wlan"]):
                        type_str = "无线网卡"
                    elif any(kw in name_lower for kw in ["ethernet", "以太网"]):
                        type_str = "有线网卡"
                    else:
                        type_str = "其他"
                    self.nic_table.setItem(row, 2, QTableWidgetItem(type_str))
                    row += 1
    def refresh_blacklist_table(self):
        self.blacklist_table.setRowCount(len(self.permanent_blacklist))
        for row, ip in enumerate(self.permanent_blacklist):
            self.blacklist_table.setItem(row, 0, QTableWidgetItem(ip))
            remove_btn = QPushButton("移除")
            remove_btn.clicked.connect(lambda checked, ip=ip: self.on_remove_from_blacklist_ip(ip))
            self.blacklist_table.setCellWidget(row, 1, remove_btn)
    def on_forget_ip(self):
        if self.show_question_dialog("确认忘记IP", "确定要忘记已记住的IP地址吗？\n\n下次启动程序时将会重新选择IP。"):
            config_file = os.path.join(get_base_path(), "config.ini")
            base_dir = get_base_path()
            try:
                test_file = os.path.join(base_dir, ".write_test")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
            except:
                import tempfile
                config_file = os.path.join(tempfile.gettempdir(), "gtanetmonitor_config.ini")
            settings = QSettings(config_file, QSettings.Format.IniFormat)
            settings.remove("RememberIP")
            settings.remove("LastSelectedIP")
            settings.sync()
            QMessageBox.information(self, "成功", "已忘记记住的IP地址，下次启动将重新选择")
    def on_blacklist_toggled(self, checked):
        if not self.driver_available:
            QMessageBox.warning(self, "功能不可用",
                                "WinDivert 驱动不可用，无法使用黑名单功能。\n\n"
                                "请以管理员身份重新运行程序。")
            self.blacklist_enabled.setChecked(False)
            return
        if checked:
            for ip in self.permanent_blacklist:
                self.blocker.block_ip(ip, permanent=True)
            QMessageBox.information(self, "黑名单", f"已启用黑名单，共 {len(self.permanent_blacklist)} 个IP被永久阻断")
        else:
            for ip in list(self.permanent_blacklist):
                self.blocker.unblock_ip(ip)
            QMessageBox.information(self, "黑名单", "已禁用黑名单，所有IP已解除阻断")
    def on_add_to_blacklist(self):
        if not self.driver_available:
            QMessageBox.warning(self, "功能不可用",
                                "WinDivert 驱动不可用，无法添加黑名单。\n\n"
                                "请以管理员身份重新运行程序。")
            return
        ip = self.get_text_dialog("添加IP到黑名单", "请输入要拉黑的IP地址：", "例如: 192.168.1.100")
        if ip is None:
            return
        try:
            socket.inet_aton(ip)
            self.permanent_blacklist.add(ip)
            self.save_blacklist()
            self.refresh_blacklist_table()
            if self.blacklist_enabled.isChecked():
                self.blocker.block_ip(ip, permanent=True)
            self.status_label.setText(
                f"监控IP: {LOCAL_IP} | 端口: {sorted(UDP_PORTS_TO_MONITOR)} | 临时阻断: 0 | 永久黑名单: {len(self.permanent_blacklist)}")
            QMessageBox.information(self, "成功", f"已将 {ip} 添加到黑名单")
        except:
            QMessageBox.warning(self, "错误", "无效的IP地址格式")
    def on_remove_from_blacklist(self):
        selected = self.blacklist_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "警告", "请先选中要移除的IP")
            return
        row = selected[0].row()
        ip_item = self.blacklist_table.item(row, 0)
        if ip_item:
            self.on_remove_from_blacklist_ip(ip_item.text())
    def on_remove_from_blacklist_ip(self, ip):
        if ip in self.permanent_blacklist:
            self.permanent_blacklist.discard(ip)
            self.save_blacklist()
            self.refresh_blacklist_table()
            if self.blacklist_enabled.isChecked():
                self.blocker.unblock_ip(ip)
            self.status_label.setText(
                f"监控IP: {LOCAL_IP} | 端口: {sorted(UDP_PORTS_TO_MONITOR)} | 临时阻断: 0 | 永久黑名单: {len(self.permanent_blacklist)}")
            QMessageBox.information(self, "成功", f"已将 {ip} 从黑名单移除")
    def update_block_table(self):
        blocked = self.blocker.get_blocked()
        self.block_table.setRowCount(len(blocked))
        temp_count = 0
        perm_count = 0
        for row, (ip, remaining) in enumerate(blocked.items()):
            display_ip = ip
            self.block_table.setItem(row, 0, QTableWidgetItem(display_ip))
            if remaining == -1:
                status_text = "永久阻断"
                status_color = QColor(255, 100, 100)
                perm_count += 1
            else:
                status_text = f"临时阻断 ({remaining}秒)"
                status_color = QColor(255, 200, 100) if remaining <= 10 else QColor(255, 255, 200)
                temp_count += 1
            status_item = QTableWidgetItem(status_text)
            status_item.setBackground(QBrush(status_color))
            self.block_table.setItem(row, 1, status_item)
            if remaining == -1:
                unblock_btn = QPushButton("解除永久")
                unblock_btn.clicked.connect(lambda checked, ip=ip: self.on_unblock_permanent(ip))
            else:
                unblock_btn = QPushButton("解除阻断")
                unblock_btn.clicked.connect(lambda checked, ip=ip: self.on_unblock_temp(ip))
            self.block_table.setCellWidget(row, 2, unblock_btn)
        self.status_label.setText(
            f"监控IP: {LOCAL_IP} | 端口: {sorted(UDP_PORTS_TO_MONITOR)} | "
            f"临时阻断: {temp_count} | 永久黑名单: {len(self.permanent_blacklist)}"
        )
    def on_unblock_temp(self, ip):
        self.blocker.unblock_ip(ip)
    def on_unblock_permanent(self, ip):
        self.blocker.unblock_ip(ip)
        if ip in self.permanent_blacklist:
            self.permanent_blacklist.discard(ip)
            self.save_blacklist()
            self.refresh_blacklist_table()
    def on_crash_detection_toggled(self, checked):
        self.crash_detection_enabled = checked
        self.proc_monitor.set_enabled(checked)
        if checked:
            QMessageBox.information(self, "挂逼崩溃战局检测", "已开启！游戏退出时将显示退出前3秒新连接的IP")
    def on_process_exited(self, recent_ips):
        if recent_ips:
            msg = "游戏进程已退出\n\n退出前3秒内新连接的IP:\n" + "\n".join(recent_ips)
            if self.show_question_dialog("检测到新IP", msg + "\n\n是否将这些IP添加到黑名单？"):
                for ip in recent_ips:
                    self.permanent_blacklist.add(ip)
                self.save_blacklist()
                self.refresh_blacklist_table()
                if self.blacklist_enabled.isChecked():
                    for ip in recent_ips:
                        self.blocker.block_ip(ip, permanent=True)
                QMessageBox.information(self, "成功", f"已将 {len(recent_ips)} 个IP添加到黑名单")
    def on_show_private_changed(self, state):
        self.show_private_ip = (state == Qt.CheckState.Checked)
        self.refresh_display()
    def auto_refresh_unknown_geo(self):
        global geo_cache
        with data_lock:
            unknown_ips = []
            for ip, peer in list(peers_map.items()):
                if peer.location in ("未知", "查询中...", "查询超时", "查询失败"):
                    unknown_ips.append(ip)
        if not unknown_ips:
            return
        updated = False
        for ip in unknown_ips:
            if ip in geo_cache:
                del geo_cache[ip]
            location, isp, is_chinese, server_type = get_geo_info(ip)
            with data_lock:
                peer = peers_map.get(ip)
                if peer:
                    old_loc = peer.location
                    peer.location = location
                    peer.isp = isp
                    peer.is_chinese = is_chinese
                    peer.server_type = server_type
                    if location != old_loc:
                        updated = True
            time.sleep(0.05)
        if updated:
            self.refresh_display()
    def on_refresh_geo(self):
        global geo_cache
        with data_lock:
            unknown_ips = [ip for ip, peer in peers_map.items() if
                           peer.location in ("未知", "查询中...", "查询超时", "查询失败")]
        if not unknown_ips:
            QMessageBox.information(self, "提示", "没有需要重试的IP")
            return
        count = 0
        for ip in unknown_ips:
            if ip in geo_cache:
                del geo_cache[ip]
            location, isp, is_chinese, server_type = get_geo_info(ip)
            with data_lock:
                peer = peers_map.get(ip)
                if peer:
                    peer.location = location
                    peer.isp = isp
                    peer.is_chinese = is_chinese
                    peer.server_type = server_type
                    count += 1
            time.sleep(0.05)
        self.refresh_display()
        QMessageBox.information(self, "完成", f"已重新查询 {count} 个IP的地理位置")
    def refresh_display(self):
        rows = []
        with data_lock:
            for peer in list(peers_map.values()):
                stats = peer.get_summary()
                if not stats:
                    continue
                if not self.show_private_ip and (
                        peer.location == "区域网" or peer.ip.startswith(('192.168.', '10.', '172.'))):
                    continue
                rows.append({'peer': peer, 'stats': stats})
        rows.sort(key=lambda x: x['stats']['avg_speed'], reverse=True)
        lines = []
        header = (f"{pad_text('IP地址', 15)} | {pad_text('地区', 68)} | "
                  f"{pad_text('均速', 4)} | {pad_text('峰值', 4)} | {pad_text('ASN/运营商', 22)}")
        lines.append(header)
        lines.append("-" * 120)
        if not rows:
            lines.append("暂无活跃连接，等待游戏网络流量...")
        else:
            for item in rows:
                p = item['peer']
                s = item['stats']
                location_display = p.location
                if p.is_chinese:
                    location_display += " [裸连]"
                if p.server_type:
                    location_display += f" [{p.server_type}]"
                if p.using_fallback:
                    location_display += " [地区可能有误]"
                if s['is_lagger']:
                    location_display += " [疑似卡逼]"
                display_ip = p.ip
                col_ip = pad_text(display_ip, 15)
                col_loc = pad_text(location_display, 68)
                spd_str = f"{s['avg_speed']:.1f}"
                max_str = f"{s['max_speed']:.1f}"
                if s['is_lagger']:
                    spd_str = f"*{spd_str}"
                    max_str = f"*{max_str}"
                col_spd = pad_text(spd_str, 4, 'right')
                col_max = pad_text(max_str, 4, 'right')
                col_isp = pad_text(p.isp, 22)
                line = f"{col_ip} | {col_loc} | {col_spd} | {col_max} | {col_isp}"
                lines.append(line)

        self.console.setText("\n".join(lines))
    def cleanup_resources(self):
        global running
        running = False
        self.proc_monitor.stop()
        self.proc_monitor.wait()
        if hasattr(self.session_tab, 'lock_count_timer'):
            self.session_tab.lock_count_timer.stop()
        self.session_tab.session_manager.stop_all()
        if hasattr(self, 'acc_test_thread') and self.acc_test_thread.isRunning():
            self.acc_test_thread.stop()
            self.acc_test_thread.wait(2)

        self.blocker.stop()
        if self.blocker.process and self.blocker.process.is_alive():
            self.blocker.process.join(2.0)
            if self.blocker.process.is_alive():
                self.blocker.process.terminate()
                self.blocker.process.join(1.0)
    def on_detect_accelerator(self):
        if not self.driver_available:
            QMessageBox.warning(self, "功能不可用",
                                "WinDivert 驱动不可用，无法使用加速器检测功能。\n\n"
                                "请以管理员身份重新运行程序。")
            return
        phy_ip = self.phy_ip_edit.text().strip()
        virt_ip = self.virt_ip_edit.text().strip()
        if not phy_ip or not virt_ip:
            QMessageBox.warning(self, "警告", "请填写物理网卡IP和虚拟网卡IP")
            return
        if hasattr(self, 'acc_test_thread') and self.acc_test_thread.isRunning():
            self.acc_test_thread.stop()
            self.acc_test_thread.wait()
            self.detect_btn.setText("开始检测加速器")
            self.acc_output.append("\n⚠️ 检测已停止")
            return
        self.acc_output.clear()
        self.detect_btn.setEnabled(False)
        self.detect_btn.setText("停止检测")
        self.acc_test_thread = AcceleratorTestThread(phy_ip, virt_ip)
        self.acc_test_thread.output.connect(self.acc_output.append)
        self.acc_test_thread.finished_signal.connect(self.on_accelerator_test_finished)
        self.acc_test_thread.start()
    def on_accelerator_test_finished(self):
        self.detect_btn.setEnabled(self.driver_available)
        self.detect_btn.setText("开始检测加速器")
    def closeEvent(self, event):
        self.cleanup_resources()
        event.accept()
# ====================== 系统主题检测 ======================
def get_system_theme():
    if sys.platform != "win32":
        return "light"
    try:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return "dark" if value == 0 else "light"
        except:
            return "light"
    except:
        return "light"
def apply_theme(app, theme):
    if theme == "dark":
        dark_style = """
        QWidget {
            background-color: #1e1e1e;
            color: #ffffff;
        }
        QMainWindow {
            background-color: #1e1e1e;
        }
        QTextEdit {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
        }
        QTextEdit:read-only {
            background-color: #252526;
        }
        QPushButton {
            background-color: #3d3d3d;
            color: #ffffff;
            border: 1px solid #555555;
            border-radius: 4px;
            padding: 5px 10px;
        }
        QPushButton:hover {
            background-color: #4d4d4d;
            border-color: #666666;
        }
        QPushButton:pressed {
            background-color: #2d2d2d;
        }
        QPushButton:disabled {
            background-color: #2d2d2d;
            color: #666666;
        }
        QPushButton:checked {
            background-color: #4a4a4a;
            border-color: #0078d4;
        }
        QPushButton:checked:hover {
            background-color: #5a5a5a;
        }
        QTableWidget {
            background-color: #252526;
            color: #d4d4d4;
            gridline-color: #3d3d3d;
            border: 1px solid #3d3d3d;
        }
        QTableWidget::item {
            background-color: #252526;
        }
        QTableWidget::item:selected {
            background-color: #0078d4;
            color: #ffffff;
        }
        QHeaderView::section {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
            padding: 4px;
        }
        QGroupBox {
            color: #ffffff;
            border: 1px solid #3d3d3d;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QLabel {
            color: #d4d4d4;
        }
        QCheckBox {
            color: #d4d4d4;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
        }
        QCheckBox::indicator:unchecked {
            background-color: #3d3d3d;
            border: 1px solid #555555;
            border-radius: 3px;
        }
        QCheckBox::indicator:unchecked:hover {
            background-color: #4d4d4d;
        }
        QCheckBox::indicator:checked {
            background-color: #0078d4;
            border: 1px solid #0078d4;
            border-radius: 3px;
        }
        QCheckBox::indicator:checked:hover {
            background-color: #1a8ad4;
        }
        QComboBox {
            background-color: #3d3d3d;
            color: #d4d4d4;
            border: 1px solid #555555;
            border-radius: 4px;
            padding: 5px;
        }
        QComboBox:hover {
            border-color: #666666;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            background-color: #2d2d2d;
            color: #d4d4d4;
            selection-background-color: #0078d4;
            selection-color: #ffffff;
        }
        QTabWidget::pane {
            border: 1px solid #3d3d3d;
            background-color: #1e1e1e;
        }
        QTabBar::tab {
            background-color: #2d2d2d;
            color: #d4d4d4;
            padding: 8px 15px;
            border: 1px solid #3d3d3d;
            border-bottom: none;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #3d3d3d;
            color: #ffffff;
            border-bottom: 2px solid #0078d4;
        }
        QTabBar::tab:hover {
            background-color: #4d4d4d;
        }
        QLineEdit {
            background-color: #3d3d3d;
            color: #d4d4d4;
            border: 1px solid #555555;
            border-radius: 4px;
            padding: 5px;
        }
        QLineEdit:focus {
            border-color: #0078d4;
        }
        QScrollBar:vertical {
            background-color: #2d2d2d;
            width: 12px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical {
            background-color: #555555;
            min-height: 20px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #666666;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }
        QScrollBar:horizontal {
            background-color: #2d2d2d;
            height: 12px;
            border-radius: 6px;
        }
        QScrollBar::handle:horizontal {
            background-color: #555555;
            min-width: 20px;
            border-radius: 6px;
        }
        QScrollBar::handle:horizontal:hover {
            background-color: #666666;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0;
        }
        QMenuBar {
            background-color: #2d2d2d;
            color: #d4d4d4;
        }
        QMenuBar::item:selected {
            background-color: #3d3d3d;
        }
        QMenu {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
        }
        QMenu::item:selected {
            background-color: #0078d4;
            color: #ffffff;
        }
        QStatusBar {
            background-color: #1e1e1e;
            color: #d4d4d4;
        }
        QToolTip {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
        }
        QDialog {
            background-color: #1e1e1e;
        }
        QMessageBox {
            background-color: #1e1e1e;
        }
        """
        app.setStyleSheet(dark_style)
        print("[主题] 应用深色主题")
    else:
        light_style = """
        QTextEdit:read-only {
            background-color: #f8f8f8;
        }
        QTableWidget::item:selected {
            background-color: #0078d4;
            color: #ffffff;
        }
        QGroupBox {
            border: 1px solid #d0d0d0;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        """
        app.setStyleSheet(light_style)
        print("[主题] 应用浅色主题")
def clean_temp_dir():
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
        cache_dir = os.path.join(base_dir, "SessionManagerTEMP")
        if os.path.exists(cache_dir):
            try:
                shutil.rmtree(cache_dir)
                print(f"[清理] 已删除残留缓存: {cache_dir}")
            except Exception as e:
                print(f"[清理] 删除残留缓存失败（可能正在被占用）: {e}")
def main():
    import ctypes
    clean_temp_dir()
    ensure_persistent_cache()
    set_dll_search_path()
    app = QApplication(sys.argv)
    if sys.platform == "win32":
        import ctypes
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                QMessageBox.critical(None, "错误",
                                     "本程序需要管理员权限才能正常工作！\n\n"
                                     "请右键点击程序，选择\"以管理员身份运行\"。")
                sys.exit(1)
        except:
            pass
    theme = get_system_theme()
    apply_theme(app, theme)
    icon_path = get_icon_path()
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    else:
        if hasattr(sys, '_MEIPASS'):
            fallback = os.path.join(sys._MEIPASS, "ico.ico")
            if os.path.exists(fallback):
                app.setWindowIcon(QIcon(fallback))
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("GTA5_RDR2_Network_Monitor")
        except:
            pass
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
