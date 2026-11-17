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
import json
from collections import deque, defaultdict

warnings.filterwarnings("ignore", category=DeprecationWarning)

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QLabel, QMessageBox, QHeaderView,
                             QGroupBox, QFormLayout, QLineEdit,
                             QTextEdit, QComboBox, QDialog, QMenu, QSystemTrayIcon,
                             QDialogButtonBox, QCheckBox, QStackedWidget, QFrame, QSizePolicy,
                             QStyle, QToolButton)
from PySide6.QtCore import (Qt, QTimer, Signal, QThread, QEvent, QSize, QPoint, QRect,
                            QPropertyAnimation, QParallelAnimationGroup, QEasingCurve)
from PySide6.QtGui import (QColor, QBrush, QFont, QIcon, QAction, QGuiApplication, QPalette,
                           QPainter, QPen, QPixmap, QFontDatabase, QMouseEvent)


# ====================== 音效初始化 ======================
SOUND_HOTKEY_ON = "sounds/hotkey_on.wav"
SOUND_HOTKEY_OFF = "sounds/hotkey_off.wav"
SOUND_BLOCK_ALERT = "sounds/block_alert.wav"


# ====================== 全局快捷键监听线程 ======================
class HotkeyMonitorThread(threading.Thread):
    def __init__(self, main_window):
        super().__init__(daemon=True)
        self.main_window = main_window
        self.running = True
        self.solo_pressed = False
        self.lock_pressed = False

    def run(self):
        import ctypes
        VK_RMENU = 0xA5
        VK_OEM_COMMA = 0xBC
        VK_OEM_PERIOD = 0xBE
        while self.running:
            if not self.main_window.enable_hotkeys:
                time.sleep(0.1)
                continue
            try:
                right_alt = ctypes.windll.user32.GetAsyncKeyState(VK_RMENU) & 0x8000
                if right_alt:
                    comma = ctypes.windll.user32.GetAsyncKeyState(VK_OEM_COMMA) & 0x8000
                    if comma and not self.solo_pressed:
                        self.solo_pressed = True
                        self.main_window.hotkey_signal.emit('solo')
                    elif not comma:
                        self.solo_pressed = False
                    period = ctypes.windll.user32.GetAsyncKeyState(VK_OEM_PERIOD) & 0x8000
                    if period and not self.lock_pressed:
                        self.lock_pressed = True
                        self.main_window.hotkey_signal.emit('lock')
                    elif not period:
                        self.lock_pressed = False
                else:
                    self.solo_pressed = False
                    self.lock_pressed = False
            except Exception as e:
                print(f"[快捷键] 监听异常: {e}")
            time.sleep(0.05)


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


# ====================== 字体 ======================
FONT_FILE = "fonts/GTAVEnhancedSimpChinese-Regular.ttf"
APP_FONT_FAMILY = "GTAV Enhanced SimpChinese"


def init_custom_font():
    global APP_FONT_FAMILY
    path = get_resource_path(FONT_FILE)
    if not os.path.exists(path):
        print(f"[字体] 未找到字体文件: {path}，将使用系统默认字体")
        return APP_FONT_FAMILY
    font_id = QFontDatabase.addApplicationFont(path)
    if font_id >= 0:
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            APP_FONT_FAMILY = families[0]
            print(f"[字体] 已加载: {APP_FONT_FAMILY} ({path})")
            return APP_FONT_FAMILY
    print(f"[字体] 加载失败: {path}，将使用系统默认字体")
    return APP_FONT_FAMILY


# ====================== 导航图标  ======================
def nav_glyph_icon(glyph, color, size=20):
    dpr = 1.0
    screen = QApplication.primaryScreen()
    if screen is not None:
        dpr = max(1.0, float(screen.devicePixelRatio()))
    pixmap = QPixmap(int(round(size * dpr)), int(round(size * dpr)))
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
    font = QFont("Segoe Fluent Icons")
    if not QFontDatabase.hasFamily("Segoe Fluent Icons"):
        font = QFont("Segoe MDL2 Assets")
    font.setPixelSize(max(1, int(round(size * dpr * 0.8))))
    painter.setFont(font)
    painter.setPen(QColor(color))
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, glyph)
    painter.end()
    pixmap.setDevicePixelRatio(dpr)
    return QIcon(pixmap)


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
CLOUD_SAVE_SERVER_IPS = {"192.81.241.171", "192.81.241.191"}
ROCKSTAR_DOMAINS = {
    "conductor-prod.ros.rockstargames.com",
    "patches.rockstargames.com",
    "prod.cloud.rockstargames.com",
    "prod.cs.ros.rockstargames.com",
    "prod.ros.rockstargames.com",
    "prod.telemetry.ros.rockstargames.com"
}
ROCKSTAR_IP_RANGES = ["52.139."]

# ====================== 辅助函数 ======================
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

    ip2_location = None
    ip2_is_chinese = False
    ip2_isp = None

    searcher = ip2region_searcher
    if searcher is not None:
        try:
            region_raw = searcher.search(ip)
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

                country = clean(country)
                area = clean(area)
                province = clean(province)
                city = clean(city)
                isp = clean(isp)

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
    process_exited = Signal(list)

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
    output = Signal(str)
    finished_signal = Signal()

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
class SnapPreviewWindow(QWidget):
    def __init__(self):
        super().__init__(None, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint
                         | Qt.WindowType.WindowStaysOnTopHint
                         | Qt.WindowType.WindowTransparentForInput)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setObjectName("SnapPreview")

    def show_preview(self, rect):
        self._accent = get_system_accent_color()
        self.setGeometry(rect)
        self.show()
        self.raise_()

    def hide_preview(self):
        self.hide()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        accent = getattr(self, "_accent", None) or get_system_accent_color()
        fill = QColor(accent)
        fill.setAlpha(48)
        pen = QPen(accent)
        pen.setWidth(2)
        painter.setPen(pen)
        painter.setBrush(fill)
        painter.drawRoundedRect(self.rect().adjusted(3, 3, -3, -3), 10, 10)


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
        if self.solo_running:
            self.stop_solo_session()
        if self.locked_running:
            self.stop_locked_session()


# ====================== 设置对话框 ======================
class SettingsDialog(QDialog):
    def __init__(self, main_window: "MainWindow" = None):
        super().__init__(main_window)
        self.main_window = main_window
        self.setWindowTitle("软件设置")
        self.setModal(True)
        self.setFixedWidth(460)
        layout = QVBoxLayout(self)
        group_settings = QGroupBox("功能与快捷键设置")
        g_layout = QVBoxLayout(group_settings)
        self.chk_hotkeys = QCheckBox("启用快捷键卡单人战局与战局锁功能")
        self.chk_hotkeys.setChecked(self.main_window.enable_hotkeys)
        self.chk_hotkeys.toggled.connect(self.on_hotkeys_toggled)
        g_layout.addWidget(self.chk_hotkeys)
        self.chk_hotkey_sound = QCheckBox("启用快捷键音效")
        self.chk_hotkey_sound.setChecked(self.main_window.enable_hotkey_sound)
        self.chk_hotkey_sound.setEnabled(self.main_window.enable_hotkeys)
        g_layout.addWidget(self.chk_hotkey_sound)
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("快捷键触发的战局锁模式:"))
        self.combo_lock_mode = QComboBox()
        self.combo_lock_mode.addItem("端点白名单战局锁", "v2")
        self.combo_lock_mode.addItem("握手包战局锁", "v1")
        if self.main_window.hotkey_lock_mode == "v1":
            self.combo_lock_mode.setCurrentIndex(1)
        else:
            self.combo_lock_mode.setCurrentIndex(0)
        mode_layout.addWidget(self.combo_lock_mode)
        g_layout.addLayout(mode_layout)
        self.chk_minimize = QCheckBox("启用最小化到系统托盘功能")
        self.chk_minimize.setChecked(self.main_window.enable_minimize)
        g_layout.addWidget(self.chk_minimize)
        self.chk_block_sound = QCheckBox("启用阻止加入提示音")
        self.chk_block_sound.setChecked(self.main_window.enable_block_sound)
        g_layout.addWidget(self.chk_block_sound)
        layout.addWidget(group_settings)
        group_maintain = QGroupBox("其他设置")
        m_layout = QVBoxLayout(group_maintain)
        m_layout.setSpacing(2)
        m_layout.setContentsMargins(10, 10, 10, 10)
        self.forget_ip_btn = QPushButton("忘记记住的IP地址")
        self.forget_ip_btn.clicked.connect(self.main_window.on_forget_ip)
        m_layout.addWidget(self.forget_ip_btn)
        tip1 = QLabel("点击后将清除已记住的IP地址，下次启动将重新选择")
        tip1.setStyleSheet("color: gray; font-size: 9px; padding: 0px; margin: 0px;")
        tip1.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        m_layout.addWidget(tip1)
        self.fix_windivert_btn = QPushButton("尝试修复WinDivert驱动")
        self.fix_windivert_btn.clicked.connect(self.main_window.on_fix_windivert)
        if self.main_window.driver_available:
            self.fix_windivert_btn.setEnabled(False)
            self.fix_windivert_btn.setToolTip("驱动已正常，无需修复")
        m_layout.addWidget(self.fix_windivert_btn)
        tip2 = QLabel("重置当前WinDivert驱动，按下确定后将会进行清理并自动重启程序")
        tip2.setStyleSheet("color: gray; font-size: 9px; padding: 0px; margin: 0px;")
        tip2.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        m_layout.addWidget(tip2)
        layout.addWidget(group_maintain)

        group_about = QGroupBox("关于")
        about_layout = QVBoxLayout(group_about)
        about_layout.setSpacing(4)
        version_label = QLabel("版本号：Public V3.0")
        about_layout.addWidget(version_label)
        accent_hex = get_system_accent_color().name()
        author_label = QLabel(
            '作者：<a href="https://space.bilibili.com/275185681" '
            f'style="color:{accent_hex}; text-decoration:none;">@白发飘飘火柴人</a>')
        author_label.setTextFormat(Qt.TextFormat.RichText)
        author_label.setOpenExternalLinks(True)
        author_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        about_layout.addWidget(author_label)
        repo_url = "https://github.com/FlowingWhiteHairMatchstickMan/GTAO_PC_NetworkChecker"
        repo_label = QLabel(
            f'开源地址：<a href="{repo_url}" '
            f'style="color:{accent_hex}; text-decoration:none;">{repo_url}</a>')
        repo_label.setTextFormat(Qt.TextFormat.RichText)
        repo_label.setOpenExternalLinks(True)
        repo_label.setWordWrap(True)
        repo_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        about_layout.addWidget(repo_label)
        layout.addWidget(group_about)

        layout.addStretch()
        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)
        self.adjustSize()

    def on_hotkeys_toggled(self, checked):
        self.chk_hotkey_sound.setEnabled(checked)

    def accept(self):
        self.main_window.enable_hotkeys = self.chk_hotkeys.isChecked()
        self.main_window.enable_hotkey_sound = self.chk_hotkey_sound.isChecked()
        self.main_window.enable_minimize = self.chk_minimize.isChecked()
        self.main_window.enable_block_sound = self.chk_block_sound.isChecked()
        self.main_window.hotkey_lock_mode = self.combo_lock_mode.currentData()
        self.main_window.save_settings()
        print(f"[设置] 已保存: Hotkeys={self.main_window.enable_hotkeys}, LockMode={self.main_window.hotkey_lock_mode}")
        super().accept()


# ====================== 战局控制标签页 ======================
class SessionControlTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.session_manager = SessionManager()
        self.lock_count_timer = QTimer()
        self.lock_count_timer.timeout.connect(self.update_lock_count)
        self.last_played_block_count = 0
        self.current_mode = None
        self.collector_running = False
        self.collector_thread = None
        self.endpoint_last_seen = {}
        self.endpoint_lock = threading.Lock()
        self.filter_process_v2 = None
        self.msg_queue_v2 = None
        self.start_v2_thread = None
        self.blocked_count_v2 = 0
        self.v2_is_starting = False
        self.start_collecting()
        self.setup_ui()

    # ==================== 采集方法 ====================
    def start_collecting(self):
        if self.collector_running:
            return
        self.collector_running = True
        self.collector_thread = threading.Thread(target=self._collector_loop, daemon=True)
        self.collector_thread.start()

    def stop_collecting(self):
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

    # ==================== 主题相关 ====================
    def apply_running_style(self, label):
        label.setStyleSheet(f"color: {get_theme_tokens()['success']};")

    def refresh_theme_colors(self):
        if self.session_manager.solo_running:
            self.apply_running_style(self.solo_status_label)
        if self.current_mode in ("v1", "v2"):
            self.apply_running_style(self.locked_status_label)

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

        for button in (self.solo_start_btn, self.solo_stop_btn, self.locked_start_btn,
                       self.locked_start_btn_v2, self.locked_stop_btn):
            button.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)

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
            "使用建议：\n1. 先进入邀请战局。\n2. 邀请您的好友全部进入战局。\n3. 启动战局锁，此时新玩家与外挂玩家无法追入战局，但已连接的玩家不受影响。\n快捷键功能：\n按下右 ALT + ，可以快速开启关闭卡单人战局，按下右 ALT + . 可以快速开启关闭战局锁。可以在软件设置中关闭本功能。")
        tip_label.setWordWrap(True)
        font = tip_label.font()
        font.setPointSize(9)
        tip_label.setFont(font)
        tip_label.setObjectName("HintLabel")
        layout.addWidget(tip_label)

    # ==================== 卡单人战局 ====================
    def start_solo_session(self, bypass_msg=False):
        if self.current_mode == 'v2':
            self.stop_locked_session(bypass_msg=True)

        success, msg = self.session_manager.start_solo_session()
        if success:
            self.current_mode = 'solo'
            self.solo_status_label.setText("运行中")
            self.apply_running_style(self.solo_status_label)
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 卡单人战局已启动")
            if not bypass_msg:
                QMessageBox.information(self, "成功", msg)
        else:
            if not bypass_msg:
                QMessageBox.warning(self, "警告", msg)

    def stop_solo_session(self, bypass_msg=False):
        success, msg = self.session_manager.stop_solo_session()
        if success:
            self.current_mode = None
            self.solo_status_label.setText("未启动")
            self.solo_status_label.setStyleSheet("")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 卡单人战局已停止")
            if not bypass_msg:
                QMessageBox.information(self, "成功", msg)
        else:
            if not bypass_msg:
                QMessageBox.warning(self, "警告", msg)

    # ==================== 战局锁方式一 ====================
    def start_locked_session(self, bypass_msg=False):
        if self.current_mode == 'v2':
            self.stop_locked_session(bypass_msg=True)
        if self.current_mode == 'solo':
            self.stop_solo_session(bypass_msg=True)

        success, msg = self.session_manager.start_locked_session()
        if success:
            self.current_mode = 'v1'
            self.locked_status_label.setText("运行中")
            self.apply_running_style(self.locked_status_label)
            self.locked_block_count_label.setText("0")
            self.lock_count_timer.start(50)
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 握手包战局锁已启动")
            if not bypass_msg:
                QMessageBox.information(self, "成功", msg)
        else:
            if not bypass_msg:
                QMessageBox.warning(self, "警告", msg)

    # ==================== 战局锁方式二（异步启动） ====================
    class StartV2Thread(QThread):
        finished_v2 = Signal(bool, str)

        def __init__(self, parent_tab, bypass_msg=False):
            super().__init__()
            self.parent_tab = parent_tab
            self.bypass_msg = bypass_msg

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
                self.parent_tab.last_played_block_count = 0
                self.finished_v2.emit(True, msg)
            except Exception as e:
                self.finished_v2.emit(False, f"启动失败: {e}")

    def start_locked_session_v2(self, bypass_msg=False):
        if self.v2_is_starting:
            if not bypass_msg:
                QMessageBox.warning(self, "警告", "端点白名单正在启动中，请稍候...")
            return

        if self.current_mode == 'solo':
            self.stop_solo_session(bypass_msg=True)
        if self.current_mode == 'v1':
            self.stop_locked_session(bypass_msg=True)
        if self.current_mode == 'v2':
            if not bypass_msg:
                QMessageBox.warning(self, "警告", "端点白名单战局锁已在运行中")
            return

        self.v2_is_starting = True
        if not bypass_msg:
            self.locked_start_btn_v2.setEnabled(False)
            self.locked_start_btn_v2.setText("启动中...")

        self.start_v2_thread = self.StartV2Thread(self, bypass_msg)
        self.start_v2_thread.finished_v2.connect(
            lambda s, m: self._on_start_v2_finished(s, m, bypass_msg))
        self.start_v2_thread.start()

    def _on_start_v2_finished(self, success, msg, bypass_msg):
        self.v2_is_starting = False
        self.locked_start_btn_v2.setEnabled(True)
        self.locked_start_btn_v2.setText("启动端点白名单战局锁")

        if success:
            self.locked_status_label.setText("运行中")
            self.apply_running_style(self.locked_status_label)
            self.locked_block_count_label.setText("0")
            self.lock_count_timer.start(50)
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 端点白名单战局锁已启动")
            if "白名单为空" in msg:
                self.log_text.append(f"[{time.strftime('%H:%M:%S')}] [警告] {msg}")
            else:
                self.log_text.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

            if not bypass_msg:
                QMessageBox.information(self, "成功", "端点白名单战局锁已启动")
        else:
            self.current_mode = None
            if not self.collector_running:
                self.start_collecting()
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 端点白名单战局锁启动失败: {msg}")
            if not bypass_msg:
                QMessageBox.critical(self, "错误", f"启动失败: {msg}")

        self.start_v2_thread = None

    # ==================== 停止战局锁（统一） ====================
    def stop_locked_session(self, bypass_msg=False):
        if self.current_mode is None or self.current_mode == 'solo':
            if not bypass_msg:
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
                if not bypass_msg:
                    QMessageBox.information(self, "成功", msg)
            else:
                if not bypass_msg:
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
            if not bypass_msg:
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
            if self.parent.enable_block_sound and self.blocked_count_v2 > 0:
                if self.blocked_count_v2 % 10 == 0 and self.blocked_count_v2 != self.last_played_block_count:
                    self.parent.play_sound(SOUND_BLOCK_ALERT)
                    self.last_played_block_count = self.blocked_count_v2


# ====================== 主窗口 ======================
class MainWindow(QMainWindow):
    hotkey_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self._opacity_animation = None
        self._geometry_animation = None
        self._nav_animation = None
        self._window_dragging = False
        self._hiding_to_tray = False
        self._closing = False
        self._max_toggle_running = False
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)
        self.setWindowTitle("GTA 在线模式 & Red Dead 在线模式 战局管理工具")
        self.resize(1280, 760)
        self.load_settings()
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
        self.setup_tray_icon()
        self.hotkey_signal.connect(self.on_hotkey_triggered)
        self.hotkey_thread = HotkeyMonitorThread(self)
        self.hotkey_thread.start()
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
        self._last_system_theme = get_system_theme()
        self._last_system_accent = QColor(get_system_accent_color())
        self._theme_timer = QTimer(self)
        self._theme_timer.timeout.connect(self.refresh_system_theme)
        self._theme_timer.start(1500)
        try:
            QGuiApplication.styleHints().colorSchemeChanged.connect(self.refresh_system_theme)
        except Exception:
            pass
        QTimer.singleShot(180, self._apply_native_chrome)
        self._fade_in()

    def _apply_native_chrome(self):
        apply_windows_native_chrome(self, self._last_system_theme)
        self._enable_native_snap()

    def refresh_system_theme(self, *_args):
        theme = get_system_theme()
        accent = get_system_accent_color()
        old_theme = getattr(self, "_last_system_theme", None)
        old_accent = getattr(self, "_last_system_accent", None)
        theme_changed = theme != old_theme
        accent_changed = old_accent is None or accent.rgba() != old_accent.rgba()
        if not theme_changed and not accent_changed:
            return

        self._last_system_theme = theme
        self._last_system_accent = QColor(accent)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, theme)
        self._apply_native_chrome()
        self.refresh_dynamic_colors()
        changes = []
        if theme_changed:
            changes.append(f"主题={theme}")
        if accent_changed:
            changes.append(f"强调色={accent.name()}")
        print(f"[主题] 系统外观已同步: {', '.join(changes)}")

    def refresh_dynamic_colors(self):
        if hasattr(self, "session_tab"):
            self.session_tab.refresh_theme_colors()
        if hasattr(self, "navigation_buttons"):
            self._update_nav_icons()
        if hasattr(self, "block_table"):
            self.update_block_table()

    # ====================== 设置与音效 ======================
    def load_settings(self):
        config_file = os.path.join(get_base_path(), "config.json")
        self.settings_data = {}
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.settings_data = json.load(f)
            except Exception as e:
                print(f"[配置] 读取 config.json 失败: {e}")
        self.enable_hotkeys = self.settings_data.get("EnableHotkeys", True)
        self.enable_hotkey_sound = self.settings_data.get("EnableHotkeySound", True)
        self.enable_minimize = self.settings_data.get("EnableMinimize", True)
        self.enable_block_sound = self.settings_data.get("EnableBlockSound", True)
        self.hotkey_lock_mode = self.settings_data.get("HotkeyLockMode", "v2")
        print(
            f"[设置] 加载完成: Hotkeys={self.enable_hotkeys}, Sound={self.enable_hotkey_sound}, Min={self.enable_minimize}, BlockSound={self.enable_block_sound}, LockMode={self.hotkey_lock_mode}")

    def save_settings(self):
        config_file = os.path.join(get_base_path(), "config.json")
        self.settings_data["EnableHotkeys"] = self.enable_hotkeys
        self.settings_data["EnableHotkeySound"] = self.enable_hotkey_sound
        self.settings_data["EnableMinimize"] = self.enable_minimize
        self.settings_data["EnableBlockSound"] = self.enable_block_sound
        self.settings_data["HotkeyLockMode"] = self.hotkey_lock_mode
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.settings_data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"[配置] 保存 config.json 失败: {e}")

    def play_sound(self, sound_path):
        resolved_path = get_resource_path(sound_path)
        print(f"[音效] 尝试播放: {resolved_path}")
        if not os.path.exists(resolved_path):
            if os.path.exists(sound_path):
                resolved_path = sound_path
            else:
                print(f"[音效] 文件不存在: {resolved_path} 或 {sound_path}")
                return
        try:
            import winsound
            winsound.PlaySound(resolved_path, winsound.SND_FILENAME | winsound.SND_ASYNC)
        except Exception as e:
            print(f"[音效] 播放失败: {e}")

    # ====================== 系统托盘 ======================
    def setup_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            self.tray_icon.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        tray_menu = QMenu(self)
        show_action = QAction("打开程序", self)
        show_action.triggered.connect(self.show_normal)
        quit_action = QAction("关闭程序", self)
        quit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_normal()

    def _animate_opacity(self, start, end, duration=170, on_finished=None):
        if getattr(self, "_opacity_animation", None) is not None:
            self._opacity_animation.stop()
        self.setWindowOpacity(start)
        animation = QPropertyAnimation(self, b"windowOpacity", self)
        animation.setDuration(duration)
        animation.setStartValue(start)
        animation.setEndValue(end)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        if on_finished is not None:
            animation.finished.connect(on_finished)
        self._opacity_animation = animation
        animation.start()

    def _fade_in(self, duration=180):
        self.setWindowOpacity(0.0)
        self.show()
        self.raise_()
        self.activateWindow()
        self._animate_opacity(0.0, 1.0, duration)

    def show_normal(self):
        if getattr(self, "_hiding_to_tray", False):
            self._hiding_to_tray = False
            if getattr(self, "_opacity_animation", None) is not None:
                self._opacity_animation.stop()
            self.setWindowOpacity(1.0)
        was_visible = self.isVisible()
        if not was_visible:
            self.setWindowOpacity(0.0)
        if self.isMaximized():
            self.showMaximized()
        else:
            self.showNormal()
        self.activateWindow()
        if not was_visible:
            self._animate_opacity(0.0, 1.0, 180)

    def quit_app(self):
        print("[系统] 托盘菜单请求退出")
        self.close()

    def changeEvent(self, event):
        if event.type() == QEvent.Type.WindowStateChange:
            if self.isMinimized() and self.enable_minimize:
                event.ignore()
                self.minimize_window()
            else:
                super().changeEvent(event)

    def closeEvent(self, event):
        if getattr(self, "_closing", False):
            event.accept()
            return
        if not self.isVisible():
            event.accept()
            self._finalize_close()
            return
        self._closing = True
        event.ignore()
        self._animate_opacity(self.windowOpacity(), 0.0, 150, self._finalize_close)

    def _finalize_close(self):
        print("[系统] 执行清理资源并彻底退出")
        self.cleanup_resources()
        if hasattr(self, 'tray_icon'):
            self.tray_icon.hide()
        app = QApplication.instance()
        if app is not None:
            app.quit()
        os._exit(0)

    # ====================== 快捷键处理 ======================
    def on_hotkey_triggered(self, action):
        if not self.enable_hotkeys:
            return
        tab = self.session_tab
        if action == 'solo':
            print("[快捷键] 触发: 切换卡单人战局")
            if tab.session_manager.solo_running:
                tab.stop_solo_session(bypass_msg=True)
                if self.enable_hotkey_sound:
                    self.play_sound(SOUND_HOTKEY_OFF)
            else:
                tab.start_solo_session(bypass_msg=True)
                if self.enable_hotkey_sound:
                    self.play_sound(SOUND_HOTKEY_ON)
        elif action == 'lock':
            print(f"[快捷键] 触发: 切换战局锁 (模式: {self.hotkey_lock_mode})")
            if tab.v2_is_starting:
                print("[快捷键] 白名单正在启动，忽略按键")
                return
            is_running = (tab.current_mode == 'v1' or tab.current_mode == 'v2')
            if is_running:
                tab.stop_locked_session(bypass_msg=True)
                if self.enable_hotkey_sound:
                    self.play_sound(SOUND_HOTKEY_OFF)
            else:
                if self.hotkey_lock_mode == 'v1':
                    tab.start_locked_session(bypass_msg=True)
                else:
                    tab.start_locked_session_v2(bypass_msg=True)
                if self.enable_hotkey_sound:
                    self.play_sound(SOUND_HOTKEY_ON)

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
        self.session_tab.solo_start_btn.setEnabled(False)
        self.session_tab.solo_stop_btn.setEnabled(False)
        self.session_tab.locked_start_btn.setEnabled(False)
        self.session_tab.locked_stop_btn.setEnabled(False)
        self.session_tab.locked_start_btn_v2.setEnabled(False)
        self.session_tab.solo_start_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.solo_stop_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.locked_start_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.locked_stop_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.locked_start_btn_v2.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.solo_start_btn.setStyleSheet("QPushButton { color: gray; }")
        self.session_tab.solo_stop_btn.setStyleSheet("QPushButton { color: gray; }")
        self.session_tab.locked_start_btn.setStyleSheet("QPushButton { color: gray; }")
        self.session_tab.locked_stop_btn.setStyleSheet("QPushButton { color: gray; }")
        self.session_tab.locked_start_btn_v2.setStyleSheet("QPushButton { color: gray; }")
        self.session_tab.solo_status_label.setText("❌ 不可用")
        self.session_tab.solo_status_label.setStyleSheet("color: gray;")
        self.session_tab.locked_status_label.setText("❌ 不可用")
        self.session_tab.locked_status_label.setStyleSheet("color: gray;")
        self.session_tab.log_text.append("⚠️ WinDivert 驱动不可用，战局管理功能已禁用")
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
        self.detect_btn.setEnabled(False)
        self.detect_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.detect_btn.setStyleSheet("QPushButton { color: gray; }")
        self.acc_output.setPlainText(
            "⚠️ WinDivert 驱动不可用\n\n加速器检测功能已禁用。\n\n请以管理员身份重新运行程序，\n或检查杀毒软件是否阻止了 WinDivert 驱动。")
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
        config_file = os.path.join(get_base_path(), "config.json")
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
            config_file = os.path.join(tempfile.gettempdir(), "gtanetmonitor_config.json")
            print(f"[配置] 改用临时目录: {config_file}")

        current_data = {}
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    current_data = json.load(f)
            except:
                pass

        remember = current_data.get("RememberIP", False)
        last_ip = current_data.get("LastSelectedIP", "")

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
            current_data["LastSelectedIP"] = selected_ip
            current_data["RememberIP"] = remember
            try:
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(current_data, f, indent=4, ensure_ascii=False)
            except:
                pass
            return selected_ip

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
            current_data["LastSelectedIP"] = selected_ip
            current_data["RememberIP"] = remember_checkbox.isChecked()
            try:
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(current_data, f, indent=4, ensure_ascii=False)
            except:
                pass
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
        self.monitor_tab = QWidget()
        self.acc_tab = QWidget()
        self.session_tab = SessionControlTab(self)

        layout = QVBoxLayout(self.monitor_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont(APP_FONT_FAMILY, 10))
        layout.addWidget(self.console)
        btn_layout = QHBoxLayout()
        self.crash_btn = QPushButton("挂逼崩溃战局检测")
        self.crash_btn.setCheckable(True)
        self.crash_btn.toggled.connect(self.on_crash_detection_toggled)
        self.refresh_geo_btn = QPushButton("重试未知地理位置")
        self.refresh_geo_btn.clicked.connect(self.on_refresh_geo)
        self.crash_btn.hide()
        self.refresh_geo_btn.hide()
        btn_layout.addWidget(self.crash_btn)
        btn_layout.addWidget(self.refresh_geo_btn)
        layout.addLayout(btn_layout)
        tip = QLabel("卡逼判定规则：IP定位位置在国内或距离您物理位置过远，连接比其他玩家速率过大，或对方网络环境未启用upnp被游戏转入中转服务器连接。")
        tip.setWordWrap(True)
        tip.setObjectName("HintLabel")
        layout.addWidget(tip)

        self.setup_accelerator_tab()
        self.page_stack = QStackedWidget()
        self.page_stack.addWidget(self.monitor_tab)
        self.page_stack.addWidget(self.acc_tab)
        self.page_stack.addWidget(self.session_tab)

        central = QWidget()
        central.setObjectName("MainClientArea")
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.title_bar = QWidget()
        self.title_bar.setObjectName("IntegratedTitleBar")
        self.title_bar.setFixedHeight(32)
        self.title_bar.installEventFilter(self)
        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(14, 0, 0, 0)
        title_layout.setSpacing(0)
        self.window_title_label = QLabel("GTA 在线模式 & Red Dead 在线模式 战局管理工具")
        self.window_title_label.setObjectName("WindowTitleLabel")
        self.window_title_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        title_layout.addWidget(self.window_title_label, 1)
        self.min_button = QToolButton()
        self.min_button.setObjectName("WindowControlButton")
        self.min_button.setText("\uE921")
        self.min_button.setToolTip("最小化")
        self.min_button.clicked.connect(self.minimize_window)
        self.max_button = QToolButton()
        self.max_button.setObjectName("WindowControlButton")
        self.max_button.setText("\uE922")
        self.max_button.setToolTip("最大化")
        self.max_button.clicked.connect(self.toggle_max_restore)
        self.close_button = QToolButton()
        self.close_button.setObjectName("WindowCloseButton")
        self.close_button.setText("\uE8BB")
        self.close_button.setToolTip("关闭")
        self.close_button.clicked.connect(self.close)
        for control in (self.min_button, self.max_button, self.close_button):
            control.setFixedSize(46, 32)
            title_layout.addWidget(control)
        outer.addWidget(self.title_bar)

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(10, 4, 10, 4)
        body_layout.setSpacing(8)
        outer.addWidget(body, 1)
        root = body_layout

        self.navigation_panel = QFrame()
        self.navigation_panel.setObjectName("NavigationPanel")
        self.navigation_collapsed = False
        self.navigation_panel.setFixedWidth(240 if get_windows_build() >= 22000 else 220)
        nav_layout = QVBoxLayout(self.navigation_panel)
        nav_layout.setContentsMargins(8, 10, 8, 10)
        nav_layout.setSpacing(5)

        nav_header = QHBoxLayout()
        self.navigation_toggle = QPushButton()
        self.navigation_toggle.setObjectName("NavigationToggle")
        self.navigation_toggle.setFixedSize(38, 38)
        self.navigation_toggle.setIconSize(QSize(16, 16))
        self.navigation_toggle.setToolTip("收起导航栏")
        self.navigation_toggle.clicked.connect(self.toggle_navigation)
        nav_header.addWidget(self.navigation_toggle)
        nav_header.addStretch(1)
        nav_layout.addLayout(nav_header)
        nav_layout.addSpacing(12)

        self.navigation_buttons = []
        nav_labels = ["战局 IP 检测", "路由模式加速器检测", "网络战局锁"]
        for index, label in enumerate(nav_labels):
            button = QPushButton(label)
            button.setObjectName("NavigationButton")
            button.setIconSize(QSize(20, 20))
            button.setCheckable(True)
            button.setMinimumHeight(44)
            button.setToolTip(label)
            button.clicked.connect(lambda checked=False, i=index: self.switch_navigation_page(i))
            nav_layout.addWidget(button)
            self.navigation_buttons.append(button)
        nav_layout.addStretch(1)

        self.nav_settings_button = QPushButton("软件设置")
        self.nav_settings_button.setObjectName("NavigationButton")
        self.nav_settings_button.setIconSize(QSize(20, 20))
        self.nav_settings_button.setMinimumHeight(44)
        self.nav_settings_button.setToolTip("软件设置")
        self.nav_settings_button.clicked.connect(self.open_settings_dialog)
        nav_layout.addWidget(self.nav_settings_button)
        self._update_nav_icons()

        content_column = QVBoxLayout()
        content_column.setContentsMargins(0, 0, 0, 0)
        content_column.addWidget(self.page_stack, 1)
        content_host = QWidget()
        content_host.setLayout(content_column)

        self.right_panel = self.create_right_panel()
        self.right_panel.setFixedWidth(350)
        root.addWidget(self.navigation_panel, 0)
        root.addWidget(content_host, 1)
        root.addWidget(self.right_panel, 0)

        self.status_label = QLabel(
            f"监控IP: {LOCAL_IP} | 端口: {sorted(UDP_PORTS_TO_MONITOR)} | 临时阻断: 0 | 永久黑名单: {len(self.permanent_blacklist)}")
        self.status_label.setObjectName("StatusInfo")
        self.status_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.statusBar().addWidget(self.status_label, 1)
        self.switch_navigation_page(0)

    def _update_nav_icons(self):
        color = get_theme_tokens()["text"]
        glyphs = ["\uE701", "\uE8D7", "\uE83D", "\uE713"]
        buttons = list(self.navigation_buttons) + [self.nav_settings_button]
        for button, glyph in zip(buttons, glyphs):
            button.setIcon(nav_glyph_icon(glyph, color))
            button.setIconSize(QSize(20, 20))
        self.navigation_toggle.setIcon(nav_glyph_icon(
            "\uE76C" if self.navigation_collapsed else "\uE76B", color, 16))

    def eventFilter(self, watched, event):
        if watched is getattr(self, "title_bar", None) and isinstance(event, QMouseEvent):
            if event.type() == QEvent.Type.MouseButtonDblClick and event.button() == Qt.MouseButton.LeftButton:
                self.toggle_max_restore()
                return True
            if event.type() == QEvent.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
                self._begin_window_drag(event.globalPosition().toPoint())
                return True
            if event.type() == QEvent.Type.MouseMove and event.buttons() & Qt.MouseButton.LeftButton:
                if getattr(self, "_window_dragging", False):
                    self._update_window_drag(event.globalPosition().toPoint())
                return True
            if event.type() == QEvent.Type.MouseButtonRelease and event.button() == Qt.MouseButton.LeftButton:
                if getattr(self, "_window_dragging", False):
                    self._finish_window_drag(event.globalPosition().toPoint())
                return True
        return super().eventFilter(watched, event)

    def _screen_for(self, global_pos):
        screen = QApplication.screenAt(global_pos)
        return screen or self.screen() or QApplication.primaryScreen()

    def _snap_zone(self, global_pos):
        screen = self._screen_for(global_pos)
        if screen is None:
            return None
        avail = screen.availableGeometry()
        margin = 12
        if global_pos.y() <= avail.top() + margin:
            return "max"
        if global_pos.x() <= avail.left() + margin:
            return "left"
        if global_pos.x() >= avail.right() - margin:
            return "right"
        return None

    def _snap_rect(self, zone, global_pos):
        screen = self._screen_for(global_pos)
        avail = screen.availableGeometry()
        if zone == "max":
            return QRect(avail)
        half = avail.width() // 2
        if zone == "left":
            return QRect(avail.left(), avail.top(), half, avail.height())
        return QRect(avail.left() + half, avail.top(), avail.width() - half, avail.height())

    def _begin_window_drag(self, global_pos):
        if not hasattr(self, "_snap_preview"):
            self._snap_preview = SnapPreviewWindow()
        self._drag_start_pos = global_pos
        self._drag_offset = global_pos - self.frameGeometry().topLeft()
        self._window_dragging = True

    def _update_window_drag(self, global_pos):
        if (global_pos - self._drag_start_pos).manhattanLength() < 6:
            return
        if self.isMaximized():
            normal = getattr(self, "_normal_geometry", None)
            if normal is not None:
                screen = self._screen_for(global_pos)
                avail = screen.availableGeometry() if screen else normal
                ratio = (self._drag_start_pos.x() - avail.left()) / max(1, avail.width())
                self.setUpdatesEnabled(False)
                try:
                    self.showNormal()
                    self.setGeometry(normal)
                finally:
                    self.setUpdatesEnabled(True)
                self._drag_offset = QPoint(int(normal.width() * ratio), 16)
        self.move(global_pos - self._drag_offset)
        zone = self._snap_zone(global_pos)
        if zone:
            self._snap_preview.show_preview(self._snap_rect(zone, global_pos))
        else:
            self._snap_preview.hide_preview()

    def _finish_window_drag(self, global_pos):
        self._window_dragging = False
        if hasattr(self, "_snap_preview"):
            self._snap_preview.hide_preview()
        if (global_pos - self._drag_start_pos).manhattanLength() < 6:
            return
        zone = self._snap_zone(global_pos)
        if zone is None:
            return
        if zone == "max":
            if not self.isMaximized():
                self.toggle_max_restore()
            return
        self._animate_geometry(self.geometry(), self._snap_rect(zone, global_pos), 200)

    def nativeEvent(self, event_type, message):
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes
                msg = ctypes.cast(int(message), ctypes.POINTER(wintypes.MSG)).contents
                if msg.message == 0x0084:
                    x = ctypes.c_short(msg.lParam & 0xFFFF).value
                    y = ctypes.c_short((msg.lParam >> 16) & 0xFFFF).value
                    rect = wintypes.RECT()
                    ctypes.windll.user32.GetWindowRect(int(self.winId()), ctypes.byref(rect))
                    border = 8
                    left = x < rect.left + border
                    right = x >= rect.right - border
                    top = y < rect.top + border
                    bottom = y >= rect.bottom - border
                    if not self.isMaximized():
                        if top and left: return True, 13
                        if top and right: return True, 14
                        if bottom and left: return True, 16
                        if bottom and right: return True, 17
                        if left: return True, 10
                        if right: return True, 11
                        if top: return True, 12
                        if bottom: return True, 15
            except Exception:
                pass
        return super().nativeEvent(event_type, message)

    def _animate_geometry(self, start_rect, end_rect, duration=220, on_finished=None):
        if getattr(self, "_geometry_animation", None) is not None:
            self._geometry_animation.stop()
        self.setGeometry(start_rect)
        animation = QPropertyAnimation(self, b"geometry", self)
        animation.setDuration(duration)
        animation.setStartValue(start_rect)
        animation.setEndValue(end_rect)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        if on_finished is not None:
            animation.finished.connect(on_finished)
        self._geometry_animation = animation
        animation.start()

    def toggle_max_restore(self):
        if getattr(self, "_max_toggle_running", False):
            return
        self._max_toggle_running = True

        if self.isMaximized():
            start_rect = self.geometry()
            target = getattr(self, "_normal_geometry", None)
            if target is None:
                self._max_toggle_running = False
                self.showNormal()
                return
            self.setUpdatesEnabled(False)
            try:
                self.showNormal()
                self.setGeometry(start_rect)
            finally:
                self.setUpdatesEnabled(True)

            def finish_restore():
                self.setGeometry(target)
                self.max_button.setText("\uE922")
                self.max_button.setToolTip("最大化")
                self._max_toggle_running = False

            self._animate_geometry(start_rect, target, 220, finish_restore)
        else:
            self._normal_geometry = self.geometry()
            screen = self.screen() or QApplication.primaryScreen()
            target = screen.availableGeometry()

            def finish_maximize():
                self.showMaximized()
                self.max_button.setText("\uE923")
                self.max_button.setToolTip("还原")
                self._max_toggle_running = False

            self._animate_geometry(self.geometry(), target, 220, finish_maximize)

    def _enable_native_snap(self):
        if sys.platform != "win32":
            return
        try:
            import ctypes
            user32 = ctypes.windll.user32
            hwnd = int(self.winId())
            gwl_style = -16
            swp_nosize, swp_nomove, swp_nozorder, swp_noactivate, swp_framechanged = (
                0x0001, 0x0002, 0x0004, 0x0010, 0x0020)
            style = user32.GetWindowLongW(hwnd, gwl_style)
            style |= 0x00040000 | 0x00010000 | 0x00020000
            user32.SetWindowLongW(hwnd, gwl_style, style)
            user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0,
                                swp_nosize | swp_nomove | swp_nozorder | swp_noactivate | swp_framechanged)
            print("[窗口] 已启用原生缩放/贴边吸附")
        except Exception as e:
            print(f"[窗口] 启用原生贴边失败: {e}")

    def minimize_window(self):
        if not self.enable_minimize:
            self.showMinimized()
            return
        if getattr(self, "_hiding_to_tray", False):
            return
        print("[系统] 最小化到托盘")
        self._hiding_to_tray = True

        def finish_hide():
            self._hiding_to_tray = False
            self.hide()

        self._animate_opacity(self.windowOpacity(), 0.0, 140, finish_hide)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not self.isMaximized() and not getattr(self, "_max_toggle_running", False):
            self._normal_geometry = self.geometry()
        width = event.size().width()
        if hasattr(self, "navigation_panel"):
            should_collapse = width < 1120
            if should_collapse != getattr(self, "navigation_collapsed", False):
                self.set_navigation_collapsed(should_collapse, animate=True)
        if hasattr(self, "max_button"):
            maximized = self.isMaximized()
            self.max_button.setText("\uE923" if maximized else "\uE922")
            self.max_button.setToolTip("还原" if maximized else "最大化")

    def moveEvent(self, event):
        super().moveEvent(event)
        if not self.isMaximized() and not getattr(self, "_max_toggle_running", False):
            self._normal_geometry = self.geometry()

    def _apply_nav_labels(self, collapsed):
        labels = ["战局 IP 检测", "路由模式加速器检测", "网络战局锁"]
        for button, label in zip(self.navigation_buttons, labels):
            button.setText("" if collapsed else label)
            button.setToolTip(label)
            button.setStyleSheet("text-align: center; padding: 9px 0;" if collapsed else "")
        self.nav_settings_button.setText("" if collapsed else "软件设置")
        self.nav_settings_button.setToolTip("软件设置")
        self.nav_settings_button.setStyleSheet(
            "text-align: center; padding: 9px 0;" if collapsed else "")

    def set_navigation_collapsed(self, collapsed, animate=True):
        expanded_width = 240 if get_windows_build() >= 22000 else 220
        collapsed_width = 64 if get_windows_build() >= 22000 else 56
        target = collapsed_width if collapsed else expanded_width
        self.navigation_collapsed = collapsed

        if not collapsed:
            self._apply_nav_labels(False)
        self.navigation_toggle.setIcon(nav_glyph_icon(
            "\uE76C" if collapsed else "\uE76B", get_theme_tokens()["text"], 16))
        self.navigation_toggle.setToolTip("展开导航栏" if collapsed else "收起导航栏")

        if not animate or not self.isVisible():
            self._apply_nav_labels(collapsed)
            self.navigation_panel.setFixedWidth(target)
            return
        current = self.navigation_panel.width()
        if current == target:
            self._apply_nav_labels(collapsed)
            self.navigation_panel.setFixedWidth(target)
            return
        if getattr(self, "_nav_animation", None) is not None:
            self._nav_animation.stop()
        self._nav_animation = QParallelAnimationGroup(self)
        for prop in (b"minimumWidth", b"maximumWidth"):
            animation = QPropertyAnimation(self.navigation_panel, prop, self)
            animation.setDuration(180)
            animation.setStartValue(current)
            animation.setEndValue(target)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            self._nav_animation.addAnimation(animation)

        def finish():
            self.navigation_panel.setFixedWidth(target)
            self._apply_nav_labels(collapsed)

        self._nav_animation.finished.connect(finish)
        self._nav_animation.start()

    def toggle_navigation(self):
        self.set_navigation_collapsed(not self.navigation_collapsed)

    def switch_navigation_page(self, index):
        if not 0 <= index < 3:
            return
        self.page_stack.setCurrentIndex(index)
        for i, button in enumerate(self.navigation_buttons):
            button.setChecked(i == index)
        if index == 1:
            self.on_tab_changed(1)

    def on_tab_changed(self, index):
        if index == 1:
            self.refresh_nic_table()
            print("[UI] 切换至加速器检测页，已自动刷新网卡信息")

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
        right_layout.addWidget(block_group, 1)

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
        right_layout.addWidget(blacklist_group, 1)
        return right_widget

    def open_settings_dialog(self):
        dialog = SettingsDialog(self)
        dialog.exec()

    def setup_accelerator_tab(self):
        layout = QVBoxLayout(self.acc_tab)
        tip_label = QLabel("注意：此检测功能仅适用于\"路由模式\"的加速器。\n"
                           "如果您使用进程模式加速，将无法检测。")
        tip_label.setWordWrap(True)
        tip_label.setObjectName("AcceleratorWarning")
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
        self.acc_output.setFont(QFont(APP_FONT_FAMILY, 9))
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
            config_file = os.path.join(get_base_path(), "config.json")
            base_dir = get_base_path()
            try:
                test_file = os.path.join(base_dir, ".write_test")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
            except:
                import tempfile
                config_file = os.path.join(tempfile.gettempdir(), "gtanetmonitor_config.json")

            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    data.pop("RememberIP", None)
                    data.pop("LastSelectedIP", None)
                    with open(config_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=4, ensure_ascii=False)
                except Exception as e:
                    print(f"[配置] 忘记IP失败: {e}")

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
        tokens = get_theme_tokens()
        for row, (ip, remaining) in enumerate(blocked.items()):
            display_ip = ip
            self.block_table.setItem(row, 0, QTableWidgetItem(display_ip))
            if remaining == -1:
                status_text = "永久阻断"
                status_bg = tokens["block_perm_bg"]
                status_fg = tokens["block_perm_text"]
            else:
                status_text = f"临时阻断 ({remaining}秒)"
                if remaining <= 10:
                    status_bg = tokens["block_expire_bg"]
                    status_fg = tokens["block_expire_text"]
                else:
                    status_bg = tokens["block_temp_bg"]
                    status_fg = tokens["block_temp_text"]
                temp_count += 1
            status_item = QTableWidgetItem(status_text)
            status_item.setBackground(QBrush(QColor(status_bg)))
            status_item.setForeground(QBrush(QColor(status_fg)))
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
            location, isp, is_chinese, server_type, using_fallback = get_geo_info(ip)
            with data_lock:
                peer = peers_map.get(ip)
                if peer:
                    old_loc = peer.location
                    peer.location = location
                    peer.isp = isp
                    peer.is_chinese = is_chinese
                    peer.server_type = server_type
                    peer.using_fallback = using_fallback
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
            location, isp, is_chinese, server_type, using_fallback = get_geo_info(ip)
            with data_lock:
                peer = peers_map.get(ip)
                if peer:
                    peer.location = location
                    peer.isp = isp
                    peer.is_chinese = is_chinese
                    peer.server_type = server_type
                    peer.using_fallback = using_fallback
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
        if hasattr(self, 'hotkey_thread'):
            self.hotkey_thread.running = False
        self.proc_monitor.stop()
        self.proc_monitor.wait(1)
        if hasattr(self.session_tab, 'lock_count_timer'):
            self.session_tab.lock_count_timer.stop()
        self.session_tab.session_manager.stop_all()
        self.session_tab.stop_collecting()
        if getattr(self.session_tab, 'current_mode', None) == 'v2':
            self.session_tab.stop_locked_session(bypass_msg=True)
        elif getattr(self.session_tab, 'current_mode', None) == 'solo':
            self.session_tab.stop_solo_session(bypass_msg=True)
        if hasattr(self, 'acc_test_thread') and self.acc_test_thread.isRunning():
            self.acc_test_thread.stop()
            self.acc_test_thread.wait(1)
        self.blocker.stop()
        if self.blocker.process and self.blocker.process.is_alive():
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


# ====================== Windows DWM 原生窗口外观 / Fluent 系统主题 ======================
def get_windows_build():
    if sys.platform != "win32":
        return 0
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        try:
            value, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
            return int(value)
        finally:
            winreg.CloseKey(key)
    except Exception:
        try:
            return int(sys.getwindowsversion().build)
        except Exception:
            return 0


def get_system_accent_color():
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\DWM"
            )
            try:
                try:
                    value, _ = winreg.QueryValueEx(key, "AccentColor")
                    value = int(value)
                    return QColor(value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF)
                except OSError:
                    value, _ = winreg.QueryValueEx(key, "ColorizationColor")
                    value = int(value)
                    return QColor((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)
            finally:
                winreg.CloseKey(key)
        except Exception:
            pass
    return QColor("#0078D4")


def get_system_theme():
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
            )
            try:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            finally:
                winreg.CloseKey(key)
            return "dark" if int(value) == 0 else "light"
        except Exception:
            pass

    app = QApplication.instance()
    if isinstance(app, QApplication):
        try:
            palette = app.palette()
            return "dark" if palette.color(QPalette.ColorRole.Window).lightness() < 128 else "light"
        except Exception:
            pass
    return "light"


# ====================== 主题色板 ======================
THEME_TOKENS = {
    "light": {
        "window": "#F3F3F3",
        "surface": "#FFFFFF",
        "surface_alt": "#F8F8F8",
        "input_bg": "#FFFFFF",
        "text": "#202020",
        "secondary": "#666666",
        "border": "#E1E1E1",
        "hover": "#EEEEEE",
        "pressed": "#E5E5E5",
        "disabled": "#A0A0A0",
        "success": "#0F7B0F",
        "warning_bg": "#FFF4CE",
        "warning_border": "#E7C86A",
        "warning_text": "#6B4E00",
        "caption_hover": "rgba(0, 0, 0, 0.06)",
        "caption_pressed": "rgba(0, 0, 0, 0.10)",
        "block_perm_bg": "#FDE7E9",
        "block_perm_text": "#8E1B1B",
        "block_temp_bg": "#FFF4CE",
        "block_temp_text": "#6B4E00",
        "block_expire_bg": "#FFE3B0",
        "block_expire_text": "#7A3E00",
    },
    "dark": {
        "window": "#242424",
        "surface": "#2B2B2B",
        "surface_alt": "#333333",
        "input_bg": "#292929",
        "text": "#F5F5F5",
        "secondary": "#B8B8B8",
        "border": "#454545",
        "hover": "#3A3A3A",
        "pressed": "#414141",
        "disabled": "#777777",
        "success": "#6CCB5F",
        "warning_bg": "#3A3220",
        "warning_border": "#5B4C26",
        "warning_text": "#F3D98C",
        "caption_hover": "rgba(255, 255, 255, 0.08)",
        "caption_pressed": "rgba(255, 255, 255, 0.12)",
        "block_perm_bg": "#43272A",
        "block_perm_text": "#FFB4B4",
        "block_temp_bg": "#3A3320",
        "block_temp_text": "#F3D98C",
        "block_expire_bg": "#4A3418",
        "block_expire_text": "#FFC978",
    },
}

CURRENT_THEME = "light"


def get_theme_tokens(theme=None):
    if theme is None:
        theme = CURRENT_THEME
    return THEME_TOKENS["dark" if theme == "dark" else "light"]


def _mix_color(source, target, ratio):
    ratio = max(0.0, min(1.0, float(ratio)))
    return QColor(
        int(round(source.red() * ratio + target.red() * (1 - ratio))),
        int(round(source.green() * ratio + target.green() * (1 - ratio))),
        int(round(source.blue() * ratio + target.blue() * (1 - ratio))),
    )


def accent_selection_color(accent_color, theme):
    tokens = get_theme_tokens(theme)
    ratio = 0.68 if theme == "dark" else 0.24
    base = QColor(tokens["window"] if theme == "dark" else "#FFFFFF")
    return _mix_color(accent_color, base, ratio)


def build_theme_palette(theme, accent=None):
    tokens = get_theme_tokens(theme)
    accent_color = QColor(accent) if accent is not None else QColor("#0078D4")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(tokens["window"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.Base, QColor(tokens["input_bg"]))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(tokens["surface_alt"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(tokens["surface_alt"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.Highlight, accent_selection_color(accent_color, theme))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(tokens["surface"]))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(tokens["secondary"]))
    palette.setColor(QPalette.ColorRole.Link, accent_color)
    if hasattr(QPalette.ColorRole, "Accent"):
        palette.setColor(QPalette.ColorRole.Accent, accent_color)
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text,
                 QPalette.ColorRole.ButtonText, QPalette.ColorRole.PlaceholderText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(tokens["disabled"]))
    return palette


def _dwm_set_window_attribute(dwmapi, hwnd, attribute, value, value_type):
    import ctypes
    payload = value_type(value)
    result = dwmapi.DwmSetWindowAttribute(
        hwnd,
        ctypes.c_uint(attribute),
        ctypes.byref(payload),
        ctypes.sizeof(payload),
    )
    return result == 0, int(result)


def apply_windows_native_chrome(window, theme):
    if sys.platform != "win32":
        return False

    build = get_windows_build()
    if build < 17763:
        return False

    try:
        import ctypes
        from ctypes import wintypes

        hwnd_value = int(window.winId())
        hwnd = wintypes.HWND(hwnd_value)
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        dwmapi.DwmSetWindowAttribute.argtypes = [
            wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD
        ]
        dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long
        dark = 1 if theme == "dark" else 0
        failed = []
        dark_ok = False
        corner_ok = False

        dark_ok, hr = _dwm_set_window_attribute(dwmapi, hwnd, 20, dark, ctypes.c_int)
        if not dark_ok and build < 22000:
            dark_ok, hr = _dwm_set_window_attribute(dwmapi, hwnd, 19, dark, ctypes.c_int)
        if not dark_ok:
            failed.append(f"immersive-dark=0x{hr & 0xFFFFFFFF:08X}")

        if build >= 22000:
            corner_ok, hr = _dwm_set_window_attribute(dwmapi, hwnd, 33, 2, ctypes.c_uint32)
            if not corner_ok:
                failed.append(f"rounded-corners=0x{hr & 0xFFFFFFFF:08X}")
            for attr, label in ((34, "border-default"), (35, "caption-default"), (36, "text-default")):
                ok, hr = _dwm_set_window_attribute(dwmapi, hwnd, attr, 0xFFFFFFFF, ctypes.c_uint32)
                if not ok:
                    failed.append(f"{label}=0x{hr & 0xFFFFFFFF:08X}")

        print(
            f"[DWM] 原生外观 | build={build} | HWND=0x{hwnd_value:X} | "
            f"dark-titlebar={'OK' if dark_ok else 'system-default'} | "
            f"rounded={'OK' if corner_ok else 'N/A'}"
        )
        if failed:
            print(f"[DWM] 部分 DWM 属性不可用: {'; '.join(failed)}")
        return dark_ok or corner_ok
    except Exception as e:
        print(f"[DWM] 原生窗口外观初始化失败: {e}")
        return False


def build_fluent_stylesheet(theme, accent=None):
    tokens = get_theme_tokens(theme)
    window = tokens["window"]
    surface = tokens["surface"]
    surface_alt = tokens["surface_alt"]
    input_bg = tokens["input_bg"]
    text = tokens["text"]
    secondary = tokens["secondary"]
    border = tokens["border"]
    hover = tokens["hover"]
    pressed = tokens["pressed"]
    disabled = tokens["disabled"]
    warning_bg = tokens["warning_bg"]
    warning_border = tokens["warning_border"]
    warning_text = tokens["warning_text"]
    caption_hover = tokens["caption_hover"]
    caption_pressed = tokens["caption_pressed"]
    accent_color = QColor(accent) if accent is not None else QColor("#0078D4")
    accent = accent_color.name()
    selection = accent_selection_color(accent_color, theme).name()

    root_background = window
    group_background = surface

    radius = "8px" if get_windows_build() >= 22000 else "3px"
    nav_radius = "8px" if get_windows_build() >= 22000 else "2px"
    return f"""
    QWidget {{
        color: {text};
        font-family: "{APP_FONT_FAMILY}", "Segoe UI Variable", "Segoe UI", "Microsoft YaHei UI", sans-serif;
        font-size: 9pt;
        selection-background-color: {selection};
        selection-color: {text};
    }}
    QMainWindow {{ background-color: {root_background}; }}
    #MainClientArea, QStackedWidget {{ background-color: transparent; border: none; }}
    #NavigationPanel {{ background-color: transparent; border: none; border-radius: 0; }}
    #IntegratedTitleBar {{ background-color: transparent; border: none; }}
    #WindowTitleLabel {{ font-size: 9pt; font-weight: 400; }}
    QToolButton#WindowControlButton {{
        color: {text};
        background: transparent;
        border: none;
        border-radius: 0;
        padding: 0;
        font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets";
        font-size: 10px;
    }}
    QToolButton#WindowControlButton:hover {{ background-color: {caption_hover}; }}
    QToolButton#WindowControlButton:pressed {{ background-color: {caption_pressed}; }}
    QToolButton#WindowCloseButton {{
        color: {text};
        background: transparent;
        border: none;
        border-radius: 0;
        padding: 0;
        font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets";
        font-size: 10px;
    }}
    QToolButton#WindowCloseButton:hover {{ color: #FFFFFF; background-color: #C42B1C; }}
    QToolButton#WindowCloseButton:pressed {{ color: #FFFFFF; background-color: #B22A1A; }}
    #StatusInfo {{ color: {secondary}; padding: 3px 6px; }}
    #HintLabel {{ color: {secondary}; }}
    QPushButton#NavigationToggle {{ background: transparent; border: none; border-radius: {nav_radius}; padding: 6px; }}
    QPushButton#NavigationToggle:hover {{ background-color: {hover}; }}
    QPushButton#NavigationButton {{ text-align: left; background: transparent; border: 1px solid transparent; border-radius: {nav_radius}; padding: 9px 10px; spacing: 12px; }}
    QPushButton#NavigationButton:hover {{ background-color: {hover}; }}
    QPushButton#NavigationButton:checked {{ background-color: {selection}; border-left: 3px solid {accent}; font-weight: 600; }}
    QDialog {{ background-color: {window}; }}
    #EmbeddedSettingsPage {{ background-color: transparent; }}
    QGroupBox {{
        background-color: {group_background};
        color: {text};
        border: 1px solid {border};
        border-radius: {radius};
        margin-top: 13px;
        padding: 12px 9px 8px 9px;
        font-weight: 600;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 6px;
    }}
    QPushButton {{
        color: {text};
        background-color: {surface_alt};
        border: 1px solid {border};
        border-radius: {radius};
        padding: 7px 14px;
        min-height: 18px;
    }}
    QPushButton:hover {{ background-color: {hover}; border-color: {accent}; }}
    QPushButton:pressed {{ background-color: {pressed}; }}
    QPushButton:checked {{ background-color: {selection}; border-color: {accent}; }}
    QPushButton:disabled {{ color: {disabled}; background-color: {surface}; border-color: {border}; }}
    QLineEdit {{
        color: {text}; background-color: {input_bg};
        border: 1px solid {border}; border-radius: {radius};
        padding: 7px 9px; min-height: 18px;
    }}
    QLineEdit:focus {{ border: 2px solid {accent}; padding: 6px 8px; }}
    QTextEdit {{
        color: {text}; background-color: {input_bg};
        border: 1px solid {border}; border-radius: {radius}; padding: 7px;
    }}
    QTableWidget {{
        color: {text}; background-color: {surface};
        alternate-background-color: {surface_alt};
        gridline-color: {border}; border: 1px solid {border};
        border-radius: {radius}; selection-background-color: {selection};
        selection-color: {text}; outline: 0;
    }}
    QTableWidget::item {{ padding: 5px 7px; border: none; }}
    QTableWidget::item:hover {{ background-color: {hover}; }}
    QHeaderView::section {{
        color: {text}; background-color: {surface_alt};
        border: none; border-bottom: 1px solid {border};
        padding: 8px 7px; font-weight: 600;
    }}
    QCheckBox {{ color: {text}; spacing: 8px; }}
    QTableCornerButton::section {{
        background-color: {surface_alt}; border: 1px solid {border};
    }}
    QLabel#AcceleratorWarning {{
        color: {warning_text};
        background-color: {warning_bg};
        border: 1px solid {warning_border};
        border-radius: {radius};
        padding: 8px 10px;
    }}
    QTabWidget::pane {{
        background-color: {surface}; border: 1px solid {border}; border-radius: {radius};
        top: -1px;
    }}
    QTabBar::tab {{
        color: {secondary}; background-color: transparent;
        border: 1px solid transparent; border-radius: 6px;
        padding: 8px 16px; margin: 3px 3px 5px 0;
    }}
    QTabBar::tab:selected {{ color: {text}; background-color: {selection}; border-color: {border}; }}
    QTabBar::tab:hover:!selected {{ color: {text}; background-color: {hover}; }}
    QComboBox {{
        color: {text}; background-color: {input_bg};
        border: 1px solid {border}; border-radius: {radius}; padding: 6px 9px;
    }}
    QComboBox:hover {{ border-color: {accent}; }}
    QComboBox QAbstractItemView {{
        color: {text}; background-color: {surface};
        selection-background-color: {selection}; border: 1px solid {border};
    }}
    QMenu {{ color: {text}; background-color: {surface}; border: 1px solid {border}; border-radius: {radius}; padding: 5px; }}
    QMenu::item {{ padding: 7px 28px 7px 10px; border-radius: 4px; }}
    QMenu::item:selected {{ color: {text}; background-color: {selection}; }}
    QStatusBar {{ color: {secondary}; background-color: {surface_alt}; border-top: 1px solid {border}; }}
    QToolTip {{ color: {text}; background-color: {surface}; border: 1px solid {border}; padding: 5px 7px; }}
    QScrollBar:vertical {{ background: transparent; width: 12px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {border}; min-height: 26px; border-radius: 5px; }}
    QScrollBar::handle:vertical:hover {{ background: {secondary}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {border}; min-width: 26px; border-radius: 5px; }}
    QScrollBar::handle:horizontal:hover {{ background: {secondary}; }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
    """


def apply_theme(app: QApplication, theme):
    global CURRENT_THEME
    if theme not in ("light", "dark"):
        theme = "light"
    CURRENT_THEME = theme

    build = get_windows_build()
    accent = get_system_accent_color()
    app.setPalette(build_theme_palette(theme, accent))
    app.setStyleSheet(build_fluent_stylesheet(theme, accent=accent))
    app.setFont(QFont(APP_FONT_FAMILY, 9))
    print(f"[主题] Fluent {'深色' if theme == 'dark' else '浅色'}主题已应用 | build={build}")

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
    QApplication.setQuitOnLastWindowClosed(False)
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
    init_custom_font()
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
