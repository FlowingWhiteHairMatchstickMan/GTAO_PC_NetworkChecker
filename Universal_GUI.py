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
from collections import deque, defaultdict
from collections import Counter
warnings.filterwarnings("ignore", category=DeprecationWarning)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QLabel, QMessageBox, QHeaderView,
                             QTabWidget, QGroupBox, QFormLayout, QLineEdit,
                             QTextEdit, QComboBox, QDialog,
                             QDialogButtonBox, QCheckBox)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSettings
from PyQt6.QtGui import (QColor, QBrush, QFont, QIcon, QPixmap, QPainter,
                         QImage, QLinearGradient)


# ====================== 路径辅助函数 ======================
def get_base_path():
    """获取程序所在目录（兼容开发环境和打包后的exe）"""
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            return sys._MEIPASS
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


def get_icon_path():
    icon_filename = "ico.ico"
    base = get_base_path()
    icon_path = os.path.join(base, icon_filename)
    if not os.path.exists(icon_path) and getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        alt_path = os.path.join(exe_dir, icon_filename)
        if os.path.exists(alt_path):
            return alt_path
    return icon_path


# ====================== 图片颜色提取 ======================
def extract_dominant_colors(image_path, num_colors=5):
    try:
        image = QImage(image_path)
        if image.isNull():
            return None

        scaled = image.scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatio,
                              Qt.TransformationMode.SmoothTransformation)

        colors = []
        for y in range(scaled.height()):
            for x in range(scaled.width()):
                color = scaled.pixelColor(x, y)
                if color.red() < 10 and color.green() < 10 and color.blue() < 10:
                    continue
                if color.red() > 245 and color.green() > 245 and color.blue() > 245:
                    continue
                colors.append((color.red(), color.green(), color.blue()))

        if not colors:
            return None

        counter = Counter(colors)
        most_common = counter.most_common(num_colors)

        result = []
        for (r, g, b), count in most_common:
            result.append(QColor(r, g, b))

        return result
    except Exception as e:
        print(f"[背景] 颜色提取失败: {e}")
        return None


def generate_gradient_from_image(image_path):
    colors = extract_dominant_colors(image_path, 5)
    if not colors or len(colors) < 2:
        return [
            QColor(20, 30, 48),
            QColor(40, 60, 80),
            QColor(30, 45, 65)
        ]

    colors.sort(key=lambda c: c.red() + c.green() + c.blue())

    if len(colors) > 3:
        result = [colors[0]]
        mid = len(colors) // 2
        result.append(colors[mid])
        result.append(colors[-1])
        return result
    elif len(colors) == 2:
        c1, c2 = colors[0], colors[1]
        mid = QColor(
            (c1.red() + c2.red()) // 2,
            (c1.green() + c2.green()) // 2,
            (c1.blue() + c2.blue()) // 2
        )
        return [c1, mid, c2]
    else:
        return colors


# ====================== DLL 搜索路径设置 ======================
def set_dll_search_path():
    """将程序所在目录添加到 DLL 搜索路径，确保能找到 WinDivert.dll"""
    if sys.platform != "win32":
        return
    base_dir = get_base_path()
    try:
        path_env = os.environ.get('PATH', '')
        if base_dir not in path_env.split(os.pathsep):
            os.environ['PATH'] = base_dir + os.pathsep + path_env
            print(f"[DLL] 已添加到 PATH: {base_dir}")

        if hasattr(os, 'add_dll_directory'):
            os.add_dll_directory(base_dir)
            print(f"[DLL] 已添加搜索路径: {base_dir}")
        else:
            import ctypes
            ctypes.windll.kernel32.SetDllDirectoryW(base_dir)
            print(f"[DLL] 已设置 DllDirectory: {base_dir}")

        dll_path = os.path.join(base_dir, 'WinDivert.dll')
        if os.path.exists(dll_path):
            try:
                import ctypes
                ctypes.CDLL(dll_path)
                print(f"[DLL] 已提前加载: {dll_path}")
            except Exception as e:
                print(f"[DLL] 提前加载失败: {e}")
    except Exception as e:
        print(f"[DLL] 设置搜索路径失败: {e}")


# ====================== WinDivert 驱动安装 ======================
def ensure_windivert_driver():
    """确保 WinDivert 驱动已安装并启动"""
    if sys.platform != "win32":
        return True

    try:
        w = pydivert.WinDivert("false")
        w.open()
        w.close()
        print("[驱动] 驱动已就绪")
        return True
    except Exception as e:
        print(f"[驱动] 驱动未就绪: {e}")

    try:
        if not pydivert.WinDivert.is_registered():
            print("[驱动] 尝试通过 pydivert 注册驱动...")
            pydivert.WinDivert.register()
        w = pydivert.WinDivert("false")
        w.open()
        w.close()
        print("[驱动] pydivert 注册成功")
        return True
    except Exception as e:
        print(f"[驱动] pydivert 注册失败: {e}")

    try:
        base = get_base_path()
        ctl_path = os.path.join(base, "windivertctl.exe")
        if not os.path.exists(ctl_path):
            print("[驱动] windivertctl.exe 未找到")
            return False

        print("[驱动] 使用 windivertctl.exe 安装驱动...")
        subprocess.run([ctl_path, "uninstall"], capture_output=True, shell=True, timeout=5)
        time.sleep(0.5)
        result = subprocess.run([ctl_path, "install"], capture_output=True, text=True, shell=True, timeout=10)
        if result.returncode != 0:
            print(f"[驱动] windivertctl 安装失败: {result.stderr}")
            return False
        subprocess.run(["sc", "start", "windivert"], capture_output=True, shell=True, timeout=5)
        time.sleep(2)

        w = pydivert.WinDivert("false")
        w.open()
        w.close()
        print("[驱动] 手动安装成功，驱动已就绪")
        return True
    except subprocess.TimeoutExpired:
        print("[驱动] 驱动安装超时")
        return False
    except Exception as e:
        print(f"[驱动] 手动安装失败: {e}")

    return False


def check_driver_available():
    """检查 WinDivert 驱动是否可用"""
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
CLOUD_SAVE_SERVER_IPS = {"192.81.241.171"}
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


def get_rockstar_server_type(ip, domain, asn_info):
    if ip in TRADE_SERVER_IPS:
        return "官方-交易服务器"
    elif ip in CLOUD_SAVE_SERVER_IPS:
        return "官方-云存档服务器"
    if domain:
        for rd in ROCKSTAR_DOMAINS:
            if rd in domain:
                return "官方-CDN服务器与云服务器"
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


def get_geo_info(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    if not is_public_ip(ip):
        info = ("区域网", "-", False, None)
        geo_cache[ip] = info
        return info
    try:
        domain = reverse_dns_lookup(ip)
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp,org,as"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            d = r.json()
            if d.get('status') == 'success':
                country = d.get('country', '')
                region = d.get('regionName', '')
                city = d.get('city', '')
                is_chinese = (country == '中国')
                if is_chinese:
                    location = f"{region}{city}" if city else region
                else:
                    location_parts = []
                    if country:
                        location_parts.append(country)
                    if region and region != city:
                        location_parts.append(region)
                    if city:
                        location_parts.append(city)
                    location = " ".join(location_parts[:2])
                isp_raw = d.get('isp', '')
                org_raw = d.get('org', '')
                as_raw = d.get('as', '')
                friendly_isp = get_friendly_isp_name(isp_raw, org_raw, as_raw)
                server_type = get_rockstar_server_type(ip, domain, as_raw or org_raw)
                info = (location.strip() or "未知", friendly_isp, is_chinese, server_type)
                geo_cache[ip] = info
                return info
    except Exception:
        pass
    info = ("未知", "-", False, None)
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
            return
        location, isp, is_chinese, server_type = get_geo_info(self.ip)
        self.location = location
        self.isp = isp
        self.is_chinese = is_chinese
        self.server_type = server_type

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
    try:
        if ":" in LOCAL_IP:
            local_ip, local_port = LOCAL_IP.split(":")
            local_port = int(local_port)
        else:
            local_ip = LOCAL_IP
            local_port = 0
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.bind((local_ip, local_port))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if hasattr(socket, 'SIO_RCVALL') and psutil.WINDOWS:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
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
            remote = d_ip if s_ip == local_ip else s_ip
            if remote.startswith(("224.", "239.", "255.")) or remote == local_ip:
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


# ====================== 过滤器函数（模块级，避免多进程重复启动GUI） ======================
def run_solo_filter():
    """卡单人战局过滤器（独立进程）"""
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


def run_locked_filter():
    """战局锁过滤器（独立进程）：只丢弃匹配请求包"""
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
                continue
            w.send(packet)
    except Exception as e:
        print(f"战局锁过滤器启动失败: {e}")


def blocker_process_func(local_ip, cmd_queue):
    """独立子进程函数，执行阻断过滤器"""
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


# ====================== 按需阻断管理器（优化版） ======================
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


# ====================== 背景管理类 ======================
class BackgroundManager:
    """管理窗口背景图片和渐变色"""

    def __init__(self, parent):
        self.parent = parent
        self.background_image = None
        self.gradient_colors = []
        self.image_path = None
        self.bg_mode = "gradient"
        self.theme_colors = {}
        self._load_background()

    def _load_background(self):
        """加载背景图片并提取颜色"""
        base_path = get_base_path()
        image_path = os.path.join(base_path, "background.jpg")

        if os.path.exists(image_path):
            print(f"[背景] 找到背景图片: {image_path}")
            self.image_path = image_path
            self.background_image = QPixmap(image_path)
            if not self.background_image.isNull():
                colors = generate_gradient_from_image(image_path)
                if colors and len(colors) >= 2:
                    self.gradient_colors = colors
                    self._extract_theme_colors(colors)
                    print(f"[背景] 从图片提取了 {len(colors)} 种颜色")
                    for i, c in enumerate(colors):
                        print(f"[背景] 颜色{i + 1}: RGB({c.red()}, {c.green()}, {c.blue()})")
                    self.bg_mode = "mixed"
                    return

        print("[背景] 未找到背景图片，使用默认渐变色")
        self.gradient_colors = [
            QColor(20, 30, 48),
            QColor(40, 60, 80),
            QColor(30, 45, 65)
        ]
        self._extract_theme_colors(self.gradient_colors)
        self.bg_mode = "gradient"

    def _extract_theme_colors(self, colors):
        """从提取的颜色中生成主题配色"""
        if not colors:
            return

        main_color = colors[-1] if len(colors) >= 1 else QColor(40, 60, 80)
        accent_color = colors[len(colors) // 2] if len(colors) >= 2 else QColor(30, 45, 65)
        dark_color = colors[0] if len(colors) >= 1 else QColor(20, 30, 48)

        self.theme_colors = {
            'main': main_color,
            'accent': accent_color,
            'dark': dark_color,
            'text': QColor(255, 255, 255),
            'text_secondary': QColor(212, 212, 212),
            'border': QColor(
                min(255, main_color.red() + 60),
                min(255, main_color.green() + 60),
                min(255, main_color.blue() + 60)
            ),
            'hover': QColor(
                min(255, main_color.red() + 40),
                min(255, main_color.green() + 40),
                min(255, main_color.blue() + 40)
            ),
            'selected': QColor(0, 120, 212),
        }

    def get_transparent_style(self):
        """生成完全透明的样式表"""
        c = self.theme_colors
        if not c:
            return self._get_default_transparent_style()

        main = c['main']
        accent = c['accent']
        dark = c['dark']
        border = c['border']
        hover = c['hover']

        main_rgba = f"rgba({main.red()}, {main.green()}, {main.blue()}, 80)"
        main_rgba_dark = f"rgba({dark.red()}, {dark.green()}, {dark.blue()}, 100)"
        accent_rgba = f"rgba({accent.red()}, {accent.green()}, {accent.blue()}, 100)"
        border_rgba = f"rgba({border.red()}, {border.green()}, {border.blue()}, 30)"
        hover_rgba = f"rgba({hover.red()}, {hover.green()}, {hover.blue()}, 120)"

        style = f"""
        QWidget {{
            background: transparent;
            color: rgba(255, 255, 255, 220);
            font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
        }}
        QMainWindow {{
            background: transparent;
        }}
        QTextEdit {{
            background: rgba(20, 30, 50, 60);
            color: rgba(212, 212, 212, 200);
            border: 1px solid {border_rgba};
            border-radius: 6px;
            padding: 4px;
        }}
        QTextEdit:read-only {{
            background: rgba(15, 25, 45, 40);
        }}
        QTextEdit:focus {{
            border-color: rgba(0, 120, 212, 80);
        }}
        QPushButton {{
            background: {accent_rgba};
            color: rgba(255, 255, 255, 220);
            border: 1px solid {border_rgba};
            border-radius: 6px;
            padding: 6px 14px;
        }}
        QPushButton:hover {{
            background: {hover_rgba};
            border-color: rgba({border.red()}, {border.green()}, {border.blue()}, 60);
        }}
        QPushButton:pressed {{
            background: rgba({dark.red()}, {dark.green()}, {dark.blue()}, 150);
        }}
        QPushButton:disabled {{
            background: rgba(40, 50, 60, 50);
            color: rgba(136, 136, 136, 100);
        }}
        QPushButton:checked {{
            background: rgba({main.red()}, {main.green()}, {main.blue()}, 120);
            border-color: #0078d4;
        }}
        QTableWidget {{
            background: rgba(20, 30, 50, 60);
            color: rgba(212, 212, 212, 200);
            gridline-color: {border_rgba};
            border: 1px solid {border_rgba};
            border-radius: 6px;
            selection-background-color: rgba(0, 120, 212, 80);
            selection-color: rgba(255, 255, 255, 220);
        }}
        QTableWidget::item {{
            background: transparent;
            padding: 4px;
        }}
        QTableWidget::item:selected {{
            background: rgba(0, 120, 212, 80);
            color: rgba(255, 255, 255, 220);
        }}
        QTableWidget::item:hover {{
            background: rgba(60, 90, 130, 40);
        }}
        QHeaderView::section {{
            background: rgba(40, 60, 80, 60);
            color: rgba(212, 212, 212, 180);
            border: 1px solid {border_rgba};
            padding: 5px;
            font-weight: bold;
        }}
        QTableCornerButton::section {{
            background: rgba(40, 60, 80, 40);
        }}
        QGroupBox {{
            color: rgba(255, 255, 255, 220);
            border: 1px solid {border_rgba};
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 12px;
            background: rgba(20, 30, 50, 40);
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 8px 0 8px;
            color: rgba(170, 204, 238, 200);
            font-weight: bold;
        }}
        QLabel {{
            color: rgba(212, 212, 212, 200);
            background: transparent;
        }}
        QCheckBox {{
            color: rgba(212, 212, 212, 200);
            background: transparent;
            spacing: 8px;
        }}
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border-radius: 4px;
        }}
        QCheckBox::indicator:unchecked {{
            background: rgba(40, 60, 80, 60);
            border: 1px solid {border_rgba};
        }}
        QCheckBox::indicator:unchecked:hover {{
            background: rgba(60, 80, 100, 80);
        }}
        QCheckBox::indicator:checked {{
            background: rgba(0, 120, 212, 100);
            border: 1px solid #0078d4;
        }}
        QCheckBox::indicator:checked:hover {{
            background: rgba(0, 140, 232, 120);
        }}
        QComboBox {{
            background: rgba(40, 60, 80, 60);
            color: rgba(212, 212, 212, 200);
            border: 1px solid {border_rgba};
            border-radius: 6px;
            padding: 5px 10px;
        }}
        QComboBox:hover {{
            border-color: rgba({border.red()}, {border.green()}, {border.blue()}, 60);
        }}
        QComboBox::drop-down {{
            border: none;
            width: 20px;
        }}
        QComboBox::down-arrow {{
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid rgba(200, 200, 200, 120);
            margin-right: 5px;
        }}
        QComboBox QAbstractItemView {{
            background: rgba(30, 45, 65, 160);
            color: rgba(212, 212, 212, 200);
            selection-background-color: rgba(0, 120, 212, 100);
            selection-color: rgba(255, 255, 255, 220);
            border: 1px solid {border_rgba};
        }}
        QTabWidget::pane {{
            border: 1px solid {border_rgba};
            background: rgba(20, 30, 50, 40);
            border-radius: 8px;
        }}
        QTabBar::tab {{
            background: rgba(40, 60, 80, 50);
            color: rgba(212, 212, 212, 180);
            padding: 8px 18px;
            border: 1px solid {border_rgba};
            border-bottom: none;
            margin-right: 2px;
            border-radius: 6px 6px 0 0;
        }}
        QTabBar::tab:selected {{
            background: rgba(60, 90, 120, 100);
            color: rgba(255, 255, 255, 220);
            border-bottom: 2px solid #0078d4;
        }}
        QTabBar::tab:hover {{
            background: rgba(80, 110, 140, 80);
        }}
        QLineEdit {{
            background: rgba(40, 60, 80, 60);
            color: rgba(212, 212, 212, 200);
            border: 1px solid {border_rgba};
            border-radius: 6px;
            padding: 5px 8px;
        }}
        QLineEdit:focus {{
            border-color: rgba(0, 120, 212, 80);
        }}
        QLineEdit:disabled {{
            background: rgba(40, 50, 60, 30);
            color: rgba(136, 136, 136, 100);
        }}
        QScrollBar:vertical {{
            background: rgba(30, 45, 65, 40);
            width: 10px;
            border-radius: 5px;
            margin: 2px;
        }}
        QScrollBar::handle:vertical {{
            background: rgba(80, 120, 170, 60);
            min-height: 20px;
            border-radius: 5px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: rgba(100, 150, 200, 80);
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0;
        }}
        QScrollBar:horizontal {{
            background: rgba(30, 45, 65, 40);
            height: 10px;
            border-radius: 5px;
            margin: 2px;
        }}
        QScrollBar::handle:horizontal {{
            background: rgba(80, 120, 170, 60);
            min-width: 20px;
            border-radius: 5px;
        }}
        QScrollBar::handle:horizontal:hover {{
            background: rgba(100, 150, 200, 80);
        }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0;
        }}
        QMenuBar {{
            background: rgba(30, 45, 65, 40);
            color: rgba(212, 212, 212, 200);
            border: none;
        }}
        QMenuBar::item:selected {{
            background: rgba(60, 90, 120, 80);
        }}
        QMenuBar::item:pressed {{
            background: rgba(60, 90, 120, 100);
        }}
        QMenu {{
            background: rgba(30, 45, 65, 160);
            color: rgba(212, 212, 212, 200);
            border: 1px solid {border_rgba};
            border-radius: 6px;
            padding: 4px;
        }}
        QMenu::item {{
            padding: 6px 20px;
            border-radius: 4px;
        }}
        QMenu::item:selected {{
            background: rgba(0, 120, 212, 80);
            color: rgba(255, 255, 255, 220);
        }}
        QMenu::separator {{
            height: 1px;
            background: {border_rgba};
            margin: 4px 10px;
        }}
        QStatusBar {{
            background: rgba(15, 25, 45, 40);
            color: rgba(212, 212, 212, 180);
            border: none;
        }}
        QStatusBar::item {{
            border: none;
        }}
        QToolTip {{
            background: rgba(30, 45, 65, 180);
            color: rgba(212, 212, 212, 200);
            border: 1px solid {border_rgba};
            border-radius: 4px;
            padding: 4px 8px;
        }}
        QDialog {{
            background: rgba(20, 30, 50, 200);
        }}
        QMessageBox {{
            background: rgba(20, 30, 50, 200);
        }}
        QMessageBox QPushButton {{
            min-width: 70px;
        }}
        """
        return style

    def _get_default_transparent_style(self):
        """默认透明样式（当颜色提取失败时使用）"""
        return """
        QWidget {
            background: transparent;
            color: rgba(255, 255, 255, 220);
        }
        QMainWindow {
            background: transparent;
        }
        QTextEdit {
            background: rgba(20, 30, 50, 60);
            color: rgba(212, 212, 212, 200);
            border: 1px solid rgba(100, 150, 200, 30);
            border-radius: 6px;
        }
        QPushButton {
            background: rgba(60, 90, 130, 100);
            color: rgba(255, 255, 255, 220);
            border: 1px solid rgba(100, 150, 200, 30);
            border-radius: 6px;
            padding: 6px 14px;
        }
        QPushButton:hover {
            background: rgba(80, 120, 170, 120);
        }
        QPushButton:disabled {
            background: rgba(40, 50, 60, 50);
            color: rgba(136, 136, 136, 100);
        }
        QTableWidget {
            background: rgba(20, 30, 50, 60);
            color: rgba(212, 212, 212, 200);
            gridline-color: rgba(100, 150, 200, 30);
            border: 1px solid rgba(100, 150, 200, 30);
            border-radius: 6px;
        }
        QTableWidget::item:selected {
            background: rgba(0, 120, 212, 80);
            color: rgba(255, 255, 255, 220);
        }
        QGroupBox {
            color: rgba(255, 255, 255, 220);
            border: 1px solid rgba(100, 150, 200, 30);
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 12px;
            background: rgba(20, 30, 50, 40);
        }
        QGroupBox::title {
            color: rgba(170, 204, 238, 200);
        }
        QLabel {
            color: rgba(212, 212, 212, 200);
            background: transparent;
        }
        QCheckBox {
            color: rgba(212, 212, 212, 200);
            background: transparent;
        }
        QCheckBox::indicator:unchecked {
            background: rgba(40, 60, 80, 60);
            border: 1px solid rgba(100, 150, 200, 30);
        }
        QCheckBox::indicator:checked {
            background: rgba(0, 120, 212, 100);
            border: 1px solid #0078d4;
        }
        QComboBox {
            background: rgba(40, 60, 80, 60);
            color: rgba(212, 212, 212, 200);
            border: 1px solid rgba(100, 150, 200, 30);
            border-radius: 6px;
        }
        QTabWidget::pane {
            border: 1px solid rgba(100, 150, 200, 30);
            background: rgba(20, 30, 50, 40);
            border-radius: 8px;
        }
        QTabBar::tab {
            background: rgba(40, 60, 80, 50);
            color: rgba(212, 212, 212, 180);
            padding: 8px 18px;
            border: 1px solid rgba(100, 150, 200, 30);
            border-bottom: none;
            border-radius: 6px 6px 0 0;
        }
        QTabBar::tab:selected {
            background: rgba(60, 90, 120, 100);
            color: rgba(255, 255, 255, 220);
            border-bottom: 2px solid #0078d4;
        }
        QLineEdit {
            background: rgba(40, 60, 80, 60);
            color: rgba(212, 212, 212, 200);
            border: 1px solid rgba(100, 150, 200, 30);
            border-radius: 6px;
        }
        QMenuBar {
            background: rgba(30, 45, 65, 40);
            color: rgba(212, 212, 212, 200);
            border: none;
        }
        QMenu {
            background: rgba(30, 45, 65, 160);
            color: rgba(212, 212, 212, 200);
            border: 1px solid rgba(100, 150, 200, 30);
        }
        QMenu::item:selected {
            background: rgba(0, 120, 212, 80);
            color: rgba(255, 255, 255, 220);
        }
        QStatusBar {
            background: rgba(15, 25, 45, 40);
            color: rgba(212, 212, 212, 180);
        }
        QDialog {
            background: rgba(20, 30, 50, 200);
        }
        QMessageBox {
            background: rgba(20, 30, 50, 200);
        }
        """

    def draw_background(self, painter, rect):
        """绘制背景"""
        if self.bg_mode == "image" and self.background_image:
            painter.setOpacity(0.85)
            painter.drawPixmap(rect, self.background_image.scaled(
                rect.width(), rect.height(),
                Qt.AspectRatioMode.IgnoreAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            ))
        elif self.bg_mode == "gradient" and self.gradient_colors:
            painter.setOpacity(0.9)
            gradient = QLinearGradient(0, 0, rect.width(), rect.height())
            if len(self.gradient_colors) >= 3:
                gradient.setColorAt(0, self.gradient_colors[0])
                gradient.setColorAt(0.5, self.gradient_colors[1])
                gradient.setColorAt(1, self.gradient_colors[2])
            elif len(self.gradient_colors) == 2:
                gradient.setColorAt(0, self.gradient_colors[0])
                gradient.setColorAt(1, self.gradient_colors[1])
            painter.fillRect(rect, QBrush(gradient))
        elif self.bg_mode == "mixed" and self.background_image and self.gradient_colors:
            painter.setOpacity(0.8)
            painter.drawPixmap(rect, self.background_image.scaled(
                rect.width(), rect.height(),
                Qt.AspectRatioMode.IgnoreAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            ))
            painter.setOpacity(0.4)
            gradient = QLinearGradient(0, 0, rect.width(), rect.height())
            if len(self.gradient_colors) >= 3:
                c1 = self.gradient_colors[0]
                c2 = self.gradient_colors[1]
                c3 = self.gradient_colors[2]
                gradient.setColorAt(0, QColor(c1.red(), c1.green(), c1.blue(), 60))
                gradient.setColorAt(0.5, QColor(c2.red(), c2.green(), c2.blue(), 50))
                gradient.setColorAt(1, QColor(c3.red(), c3.green(), c3.blue(), 40))
            else:
                c1 = self.gradient_colors[0]
                c2 = self.gradient_colors[1] if len(self.gradient_colors) > 1 else self.gradient_colors[0]
                gradient.setColorAt(0, QColor(c1.red(), c1.green(), c1.blue(), 60))
                gradient.setColorAt(1, QColor(c2.red(), c2.green(), c2.blue(), 40))
            painter.fillRect(rect, QBrush(gradient))
            painter.setOpacity(1.0)

# ====================== 进程监控线程（挂逼崩溃检测） ======================
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
                    packet = w.recv(timeout=100)
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
        self.locked_process = multiprocessing.Process(target=run_locked_filter, daemon=True)
        self.locked_process.start()
        return True, "战局锁已启动，新玩家无法加入"

    def stop_locked_session(self):
        if not self.locked_running:
            return False, "战局锁未运行"
        self.locked_running = False
        if self.locked_process and self.locked_process.is_alive():
            self.locked_process.terminate()
            self.locked_process.join(0.5)
        return True, "战局锁已停止"


# ====================== 战局管理选项卡 ======================
class SessionControlTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.session_manager = SessionManager()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        self.status_group = QGroupBox("当前状态")
        status_layout = QFormLayout(self.status_group)
        self.solo_status_label = QLabel("未启动")
        self.locked_status_label = QLabel("未启动")
        status_layout.addRow("卡单人战局:", self.solo_status_label)
        status_layout.addRow("战局锁:", self.locked_status_label)
        layout.addWidget(self.status_group)

        btn_group = QGroupBox("控制面板")
        btn_layout = QHBoxLayout(btn_group)
        self.solo_start_btn = QPushButton("启动卡单人战局")
        self.solo_start_btn.clicked.connect(self.start_solo_session)
        self.solo_stop_btn = QPushButton("停止卡单人战局")
        self.solo_stop_btn.clicked.connect(self.stop_solo_session)
        self.locked_start_btn = QPushButton("启动战局锁")
        self.locked_start_btn.clicked.connect(self.start_locked_session)
        self.locked_stop_btn = QPushButton("停止战局锁")
        self.locked_stop_btn.clicked.connect(self.stop_locked_session)
        btn_layout.addWidget(self.solo_start_btn)
        btn_layout.addWidget(self.solo_stop_btn)
        btn_layout.addWidget(self.locked_start_btn)
        btn_layout.addWidget(self.locked_stop_btn)
        layout.addWidget(btn_group)

        log_group = QGroupBox("操作日志")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background: rgba(15, 25, 45, 40);
                color: rgba(212, 212, 212, 200);
                border: 1px solid rgba(100, 150, 200, 20);
                border-radius: 6px;
            }
            QTextEdit:read-only {
                background: rgba(15, 25, 45, 30);
            }
            QScrollBar:vertical {
                background: rgba(30, 45, 65, 30);
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: rgba(80, 120, 170, 50);
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(100, 150, 200, 70);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
        """)
        log_layout.addWidget(self.log_text)
        layout.addWidget(log_group)

        tip_label = QLabel(
            "使用建议：\n1. 先进入邀请战局。\n2. 邀请您的好友全部进入战局。\n3. 启动战局锁，此时新玩家与外挂玩家无法追入战局，但已连接的玩家不受影响。")
        tip_label.setWordWrap(True)
        font = tip_label.font()
        font.setPointSize(12)
        tip_label.setFont(font)
        tip_label.setStyleSheet("color: rgba(170, 204, 238, 200);")
        layout.addWidget(tip_label)

    def start_solo_session(self):
        success, msg = self.session_manager.start_solo_session()
        if success:
            self.solo_status_label.setText("运行中")
            self.solo_status_label.setStyleSheet("color: rgba(102, 255, 102, 200);")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 卡单人战局已启动")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

    def stop_solo_session(self):
        success, msg = self.session_manager.stop_solo_session()
        if success:
            self.solo_status_label.setText("未启动")
            self.solo_status_label.setStyleSheet("color: rgba(255, 102, 102, 200);")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 卡单人战局已停止")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

    def start_locked_session(self):
        success, msg = self.session_manager.start_locked_session()
        if success:
            self.locked_status_label.setText("运行中")
            self.locked_status_label.setStyleSheet("color: rgba(102, 255, 102, 200);")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 战局锁已启动")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

    def stop_locked_session(self):
        success, msg = self.session_manager.stop_locked_session()
        if success:
            self.locked_status_label.setText("未启动")
            self.locked_status_label.setStyleSheet("color: rgba(255, 102, 102, 200);")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 战局锁已停止")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)


# ====================== 主窗口 ======================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GTA 在线模式 & Red Dead 在线模式 战局管理工具")

        self.resize(1200, 500)

        # 设置窗口属性以支持透明背景
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self.bg_manager = BackgroundManager(self)

        # ====================== 应用透明样式 ======================
        transparent_style = self.bg_manager.get_transparent_style()
        self.setStyleSheet(transparent_style)
        # =======================================================

        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

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

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect()
        self.bg_manager.draw_background(painter, rect)
        painter.end()
        super().paintEvent(event)

    # ====================== 通用工具函数 ======================
    def get_text_dialog(self, title, label, placeholder="", parent=None):
        dialog = QDialog(parent or self)
        dialog.setWindowTitle(title)
        dialog.setModal(True)
        dialog.setStyleSheet("""
            QDialog { background: rgba(20, 30, 50, 200); }
            QLabel { color: rgba(212, 212, 212, 200); }
            QLineEdit {
                background: rgba(40, 60, 80, 80);
                color: rgba(212, 212, 212, 200);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 5px;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 200);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
        """)

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
        """禁用依赖于 WinDivert 的功能"""
        self.session_tab.solo_start_btn.setEnabled(False)
        self.session_tab.solo_stop_btn.setEnabled(False)
        self.session_tab.locked_start_btn.setEnabled(False)
        self.session_tab.locked_stop_btn.setEnabled(False)

        self.session_tab.solo_start_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.solo_stop_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.locked_start_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.session_tab.locked_stop_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")

        self.session_tab.solo_start_btn.setStyleSheet("QPushButton { color: rgba(128, 128, 128, 100); }")
        self.session_tab.solo_stop_btn.setStyleSheet("QPushButton { color: rgba(128, 128, 128, 100); }")
        self.session_tab.locked_start_btn.setStyleSheet("QPushButton { color: rgba(128, 128, 128, 100); }")
        self.session_tab.locked_stop_btn.setStyleSheet("QPushButton { color: rgba(128, 128, 128, 100); }")

        self.session_tab.solo_status_label.setText("❌ 不可用")
        self.session_tab.solo_status_label.setStyleSheet("color: rgba(128, 128, 128, 100);")
        self.session_tab.locked_status_label.setText("❌ 不可用")
        self.session_tab.locked_status_label.setStyleSheet("color: rgba(128, 128, 128, 100);")

        self.session_tab.log_text.append("⚠️ WinDivert 驱动不可用，战局管理功能已禁用")

        self.temp_block_btn.setEnabled(False)
        self.temp_block_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.temp_block_btn.setStyleSheet("QPushButton { color: rgba(128, 128, 128, 100); }")

        self.blacklist_enabled.setEnabled(False)
        self.blacklist_enabled.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.blacklist_enabled.setStyleSheet("QCheckBox { color: rgba(128, 128, 128, 100); }")

        if hasattr(self, 'add_bl_btn'):
            self.add_bl_btn.setEnabled(False)
            self.add_bl_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
            self.add_bl_btn.setStyleSheet("QPushButton { color: rgba(128, 128, 128, 100); }")

        if hasattr(self, 'remove_bl_btn'):
            self.remove_bl_btn.setEnabled(False)
            self.remove_bl_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
            self.remove_bl_btn.setStyleSheet("QPushButton { color: rgba(128, 128, 128, 100); }")

        self.block_table.setRowCount(1)
        self.block_table.setItem(0, 0, QTableWidgetItem("⚠ 驱动不可用"))
        self.block_table.setItem(0, 1, QTableWidgetItem("功能已禁用"))
        self.block_table.setItem(0, 2, QTableWidgetItem(""))
        self.block_table.item(0, 0).setForeground(QBrush(QColor(255, 100, 100)))

        self.detect_btn.setEnabled(False)
        self.detect_btn.setToolTip("❌ WinDivert 驱动不可用，此功能已禁用")
        self.detect_btn.setStyleSheet("QPushButton { color: rgba(128, 128, 128, 100); }")

        self.acc_output.setPlainText(
            "⚠️ WinDivert 驱动不可用\n\n加速器检测功能已禁用。\n\n请以管理员身份重新运行程序，\n或检查杀毒软件是否阻止了 WinDivert 驱动。")

        self.driver_status_label = QLabel("⚠ WinDivert 驱动不可用，部分功能已禁用")
        self.driver_status_label.setStyleSheet("color: rgba(255, 107, 107, 200); font-weight: bold; padding: 2px 10px;")
        self.statusBar().addPermanentWidget(self.driver_status_label)

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
        settings = QSettings(config_file, QSettings.Format.IniFormat)
        remember = settings.value("RememberIP", False, type=bool)
        last_ip = settings.value("LastSelectedIP", "", type=str)

        current_ips = []
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    current_ips.append(addr.address)

        if remember and last_ip and last_ip in current_ips:
            print(f"使用上次选择的 IP: {last_ip}")
            return last_ip

        dialog = QDialog(self)
        dialog.setWindowTitle("选择监控的本地IP")
        dialog.setModal(True)
        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        dialog.setWindowFlags(dialog.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        dialog.setStyleSheet("""
            QDialog { background: rgba(20, 30, 50, 200); }
            QLabel { color: rgba(212, 212, 212, 200); }
            QComboBox {
                background: rgba(40, 60, 80, 80);
                color: rgba(212, 212, 212, 200);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 5px;
            }
            QComboBox:hover {
                border-color: rgba(100, 150, 200, 60);
            }
            QComboBox QAbstractItemView {
                background: rgba(30, 45, 65, 160);
                color: rgba(212, 212, 212, 200);
                selection-background-color: rgba(0, 120, 212, 100);
            }
            QCheckBox {
                color: rgba(212, 212, 212, 200);
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                background: rgba(40, 60, 80, 60);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                background: rgba(0, 120, 212, 100);
                border: 1px solid #0078d4;
                border-radius: 3px;
            }
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 200);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
        """)

        font = dialog.font()
        font.setPointSize(11)
        dialog.setFont(font)

        layout = QVBoxLayout(dialog)
        label = QLabel("请选择游戏使用的本地IP地址：")
        label.setFont(font)
        layout.addWidget(label)

        combo = QComboBox()
        combo.setFont(font)
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    combo.addItem(f"{name}: {addr.address}", addr.address)
        if combo.count() == 0:
            combo.addItem("无可用IP", "")
        if last_ip and last_ip in current_ips:
            idx = combo.findData(last_ip)
            if idx >= 0:
                combo.setCurrentIndex(idx)
        layout.addWidget(combo)

        remember_checkbox = QCheckBox("记住我的选择（下次自动使用此IP）")
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
            settings.setValue("LastSelectedIP", selected_ip)
            settings.setValue("RememberIP", remember_checkbox.isChecked())
            settings.sync()
            return selected_ip
        else:
            QMessageBox.critical(self, "错误", "未选择有效IP，程序退出")
            sys.exit(1)

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

    def setup_ui(self):
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid rgba(100, 150, 200, 30);
                background: rgba(20, 30, 50, 40);
                border-radius: 8px;
            }
            QTabBar::tab {
                background: rgba(40, 60, 80, 40);
                color: rgba(212, 212, 212, 180);
                padding: 8px 15px;
                border: 1px solid rgba(100, 150, 200, 30);
                border-bottom: none;
                margin-right: 2px;
                border-radius: 5px 5px 0 0;
            }
            QTabBar::tab:selected {
                background: rgba(60, 90, 120, 80);
                color: rgba(255, 255, 255, 220);
                border-bottom: 2px solid #0078d4;
            }
            QTabBar::tab:hover {
                background: rgba(80, 110, 140, 60);
            }
        """)

        self.monitor_tab = QWidget()
        self.acc_tab = QWidget()
        self.session_tab = SessionControlTab(self)

        layout = QVBoxLayout(self.monitor_tab)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        self.console.setStyleSheet("""
            QTextEdit {
                background: rgba(20, 30, 50, 50);
                color: rgba(212, 212, 212, 200);
                border: 1px solid rgba(100, 150, 200, 25);
                border-radius: 6px;
            }
            QTextEdit:read-only {
                background: rgba(15, 25, 45, 30);
            }
            QScrollBar:vertical {
                background: rgba(30, 45, 65, 30);
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: rgba(80, 120, 170, 50);
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(100, 150, 200, 70);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
        """)
        layout.addWidget(self.console)

        btn_layout = QHBoxLayout()
        self.crash_btn = QPushButton("挂逼崩溃战局检测")
        self.crash_btn.setCheckable(True)
        self.crash_btn.toggled.connect(self.on_crash_detection_toggled)
        self.crash_btn.setStyleSheet("""
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
            QPushButton:checked {
                background: rgba(70, 110, 160, 120);
                border-color: #0078d4;
            }
        """)

        self.refresh_geo_btn = QPushButton("重试未知地理位置")
        self.refresh_geo_btn.clicked.connect(self.on_refresh_geo)
        self.refresh_geo_btn.setStyleSheet("""
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
        """)

        btn_layout.addWidget(self.crash_btn)
        btn_layout.addWidget(self.refresh_geo_btn)

        self.forget_ip_btn = QPushButton("忘记记住的IP")
        self.forget_ip_btn.clicked.connect(self.on_forget_ip)
        self.forget_ip_btn.setStyleSheet("""
            QPushButton {
                background: rgba(180, 60, 60, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(200, 80, 80, 50);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(200, 80, 80, 120);
            }
        """)
        btn_layout.addWidget(self.forget_ip_btn)

        tip = QLabel("卡逼判定：平均速率>100KB/s 或 峰值>100KB/s")
        tip.setStyleSheet("color: rgba(255, 200, 50, 220);")
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
        self.status_label.setStyleSheet("color: rgba(200, 200, 200, 200); padding: 2px 10px;")
        self.statusBar().addWidget(self.status_label)

    def create_right_panel(self):
        right_widget = QWidget()
        right_widget.setMaximumWidth(350)
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(5, 5, 5, 5)
        right_layout.setSpacing(10)

        block_group = QGroupBox("阻断连接")
        block_group.setStyleSheet("""
            QGroupBox {
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: rgba(20, 30, 50, 30);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: rgba(255, 80, 80, 230);
                font-weight: bold;
            }
        """)
        block_layout = QVBoxLayout(block_group)

        self.block_table = QTableWidget()
        self.block_table.setColumnCount(3)
        self.block_table.setHorizontalHeaderLabels(["IP地址", "状态", "操作"])
        self.block_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.block_table.setStyleSheet("""
            QTableWidget {
                background: rgba(20, 30, 50, 50);
                color: rgba(212, 212, 212, 200);
                gridline-color: rgba(100, 150, 200, 25);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 6px;
            }
            QTableWidget::item {
                background: transparent;
            }
            QTableWidget::item:selected {
                background: rgba(0, 120, 212, 80);
                color: rgba(255, 255, 255, 220);
            }
            QHeaderView::section {
                background: rgba(40, 60, 80, 50);
                color: rgba(212, 212, 212, 180);
                border: 1px solid rgba(100, 150, 200, 25);
                padding: 4px;
            }
        """)
        block_layout.addWidget(self.block_table)

        temp_block_btn_layout = QHBoxLayout()
        self.temp_block_btn = QPushButton("添加IP临时阻断")
        self.temp_block_btn.clicked.connect(self.on_temp_block_ip)
        self.temp_block_btn.setStyleSheet("""
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
        """)
        temp_block_btn_layout.addWidget(self.temp_block_btn)
        block_layout.addLayout(temp_block_btn_layout)
        right_layout.addWidget(block_group)

        blacklist_group = QGroupBox("黑名单设置")
        blacklist_group.setStyleSheet("""
            QGroupBox {
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: rgba(20, 30, 50, 30);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: rgba(255, 80, 80, 230);
                font-weight: bold;
            }
        """)
        blacklist_layout = QVBoxLayout(blacklist_group)

        self.blacklist_enabled = QCheckBox("启用黑名单")
        self.blacklist_enabled.setChecked(False)
        self.blacklist_enabled.toggled.connect(self.on_blacklist_toggled)
        self.blacklist_enabled.setStyleSheet("color: rgba(212, 212, 212, 200);")
        blacklist_layout.addWidget(self.blacklist_enabled)

        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(2)
        self.blacklist_table.setHorizontalHeaderLabels(["IP地址", "操作"])
        self.blacklist_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.blacklist_table.setStyleSheet("""
            QTableWidget {
                background: rgba(20, 30, 50, 50);
                color: rgba(212, 212, 212, 200);
                gridline-color: rgba(100, 150, 200, 25);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 6px;
            }
            QTableWidget::item {
                background: transparent;
            }
            QTableWidget::item:selected {
                background: rgba(0, 120, 212, 80);
                color: rgba(255, 255, 255, 220);
            }
            QHeaderView::section {
                background: rgba(40, 60, 80, 50);
                color: rgba(212, 212, 212, 180);
                border: 1px solid rgba(100, 150, 200, 25);
                padding: 4px;
            }
        """)
        self.refresh_blacklist_table()
        blacklist_layout.addWidget(self.blacklist_table)

        bl_btn_layout = QHBoxLayout()
        self.add_bl_btn = QPushButton("添加IP到黑名单")
        self.add_bl_btn.clicked.connect(self.on_add_to_blacklist)
        self.add_bl_btn.setStyleSheet("""
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
        """)

        self.remove_bl_btn = QPushButton("从黑名单移除")
        self.remove_bl_btn.clicked.connect(self.on_remove_from_blacklist)
        self.remove_bl_btn.setStyleSheet("""
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
        """)

        bl_btn_layout.addWidget(self.add_bl_btn)
        bl_btn_layout.addWidget(self.remove_bl_btn)
        blacklist_layout.addLayout(bl_btn_layout)
        right_layout.addWidget(blacklist_group)

        forget_group = QGroupBox("IP设置")
        forget_group.setStyleSheet("""
            QGroupBox {
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: rgba(20, 30, 50, 30);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: rgba(170, 204, 238, 180);
            }
        """)
        forget_layout = QVBoxLayout(forget_group)

        self.forget_ip_setting_btn = QPushButton("忘记记住的IP地址")
        self.forget_ip_setting_btn.clicked.connect(self.on_forget_ip)
        self.forget_ip_setting_btn.setStyleSheet("""
            QPushButton {
                background: rgba(180, 60, 60, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(200, 80, 80, 50);
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: rgba(200, 80, 80, 120);
            }
        """)
        forget_layout.addWidget(self.forget_ip_setting_btn)

        forget_tip = QLabel("点击后将清除已记住的IP地址，\n下次启动将重新选择")
        forget_tip.setStyleSheet("color: rgba(136, 170, 204, 160); font-size: 9px;")
        forget_layout.addWidget(forget_tip)

        right_layout.addWidget(forget_group)

        return right_widget

    def setup_accelerator_tab(self):
        layout = QVBoxLayout(self.acc_tab)

        tip_label = QLabel("注意：此检测功能仅适用于\"路由模式\"的加速器。\n"
                           "如果您使用进程模式加速，将无法检测。")
        tip_label.setWordWrap(True)
        tip_label.setStyleSheet("color: rgba(255, 170, 68, 200); background-color: rgba(255, 243, 205, 20); "
                                "border: 1px solid rgba(255, 238, 186, 30); padding: 5px; border-radius: 6px;")
        layout.addWidget(tip_label)

        info_group = QGroupBox("当前网络接口信息")
        info_group.setStyleSheet("""
            QGroupBox {
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: rgba(20, 30, 50, 30);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: rgba(170, 204, 238, 180);
            }
        """)
        info_layout = QVBoxLayout(info_group)

        self.nic_table = QTableWidget()
        self.nic_table.setColumnCount(3)
        self.nic_table.setHorizontalHeaderLabels(["接口名称", "IP地址", "类型"])
        self.nic_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.nic_table.setStyleSheet("""
            QTableWidget {
                background: rgba(20, 30, 50, 50);
                color: rgba(212, 212, 212, 200);
                gridline-color: rgba(100, 150, 200, 25);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 6px;
            }
            QTableWidget::item {
                background: transparent;
            }
            QTableWidget::item:selected {
                background: rgba(0, 120, 212, 80);
                color: rgba(255, 255, 255, 220);
            }
            QHeaderView::section {
                background: rgba(40, 60, 80, 50);
                color: rgba(212, 212, 212, 180);
                border: 1px solid rgba(100, 150, 200, 25);
                padding: 4px;
            }
        """)
        info_layout.addWidget(self.nic_table)

        refresh_nic_btn = QPushButton("刷新网卡信息")
        refresh_nic_btn.clicked.connect(self.refresh_nic_table)
        refresh_nic_btn.setStyleSheet("""
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
        """)
        info_layout.addWidget(refresh_nic_btn)
        layout.addWidget(info_group)

        input_group = QGroupBox("IP地址配置")
        input_group.setStyleSheet("""
            QGroupBox {
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: rgba(20, 30, 50, 30);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: rgba(170, 204, 238, 180);
            }
        """)
        input_layout = QFormLayout(input_group)
        self.phy_ip_edit = QLineEdit()
        self.phy_ip_edit.setPlaceholderText("例如: 192.168.1.100")
        self.phy_ip_edit.setStyleSheet("""
            QLineEdit {
                background: rgba(40, 60, 80, 80);
                color: rgba(212, 212, 212, 200);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 5px;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
        """)
        self.virt_ip_edit = QLineEdit()
        self.virt_ip_edit.setPlaceholderText("例如: 172.20.10.1")
        self.virt_ip_edit.setStyleSheet("""
            QLineEdit {
                background: rgba(40, 60, 80, 80);
                color: rgba(212, 212, 212, 200);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 5px;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
        """)
        input_layout.addRow("物理网卡IP:", self.phy_ip_edit)
        input_layout.addRow("虚拟网卡IP:", self.virt_ip_edit)
        layout.addWidget(input_group)

        output_group = QGroupBox("检测输出")
        output_group.setStyleSheet("""
            QGroupBox {
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 30);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: rgba(20, 30, 50, 30);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: rgba(170, 204, 238, 180);
            }
        """)
        output_layout = QVBoxLayout(output_group)
        self.acc_output = QTextEdit()
        self.acc_output.setReadOnly(True)
        self.acc_output.setFont(QFont("Consolas", 9))
        self.acc_output.setStyleSheet("""
            QTextEdit {
                background: rgba(15, 25, 45, 40);
                color: rgba(212, 212, 212, 200);
                border: 1px solid rgba(100, 150, 200, 20);
                border-radius: 6px;
            }
            QTextEdit:read-only {
                background: rgba(15, 25, 45, 30);
            }
            QScrollBar:vertical {
                background: rgba(30, 45, 65, 30);
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: rgba(80, 120, 170, 50);
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(100, 150, 200, 70);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
        """)
        output_layout.addWidget(self.acc_output)
        layout.addWidget(output_group)

        self.detect_btn = QPushButton("开始检测加速器")
        self.detect_btn.setMinimumHeight(40)
        self.detect_btn.clicked.connect(self.on_detect_accelerator)
        self.detect_btn.setStyleSheet("""
            QPushButton {
                background: rgba(60, 90, 130, 100);
                color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(100, 150, 200, 40);
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: rgba(80, 120, 170, 120);
            }
            QPushButton:disabled {
                background: rgba(40, 50, 60, 60);
                color: rgba(136, 136, 136, 100);
            }
        """)
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
            remove_btn.setStyleSheet("""
                QPushButton {
                    background: rgba(180, 60, 60, 100);
                    color: rgba(255, 255, 255, 220);
                    border: 1px solid rgba(200, 80, 80, 50);
                    border-radius: 4px;
                    padding: 3px 8px;
                }
                QPushButton:hover {
                    background: rgba(200, 80, 80, 120);
                }
            """)
            self.blacklist_table.setCellWidget(row, 1, remove_btn)

    # ------------------- 槽函数 -------------------
    def on_forget_ip(self):
        if self.show_question_dialog("确认忘记IP", "确定要忘记已记住的IP地址吗？\n\n下次启动程序时将会重新选择IP。"):
            config_file = os.path.join(get_base_path(), "config.ini")
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
                unblock_btn.setStyleSheet("""
                    QPushButton {
                        background: rgba(180, 60, 60, 100);
                        color: rgba(255, 255, 255, 220);
                        border: 1px solid rgba(200, 80, 80, 50);
                        border-radius: 4px;
                        padding: 3px 8px;
                    }
                    QPushButton:hover {
                        background: rgba(200, 80, 80, 120);
                    }
                """)
            else:
                unblock_btn = QPushButton("解除阻断")
                unblock_btn.clicked.connect(lambda checked, ip=ip: self.on_unblock_temp(ip))
                unblock_btn.setStyleSheet("""
                    QPushButton {
                        background: rgba(60, 130, 60, 100);
                        color: rgba(255, 255, 255, 220);
                        border: 1px solid rgba(80, 200, 80, 50);
                        border-radius: 4px;
                        padding: 3px 8px;
                    }
                    QPushButton:hover {
                        background: rgba(80, 200, 80, 120);
                    }
                """)
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
        global running
        running = False
        self.proc_monitor.stop()
        self.blocker.stop()
        event.accept()


# ====================== 系统主题检测 ======================
def get_system_theme():
    """检测 Windows 系统主题（深色/浅色）"""
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


def apply_theme(app, theme, theme_colors=None):
    """应用主题样式（固定白色文字）"""
    if theme == "dark":
        # 使用固定的深色样式，文字固定为白色
        dark_style = """
        QWidget {
            background-color: rgba(30, 40, 60, 160);
            color: rgba(255, 255, 255, 220);
        }
        QMainWindow {
            background: transparent;
        }
        QTextEdit {
            background-color: rgba(20, 30, 50, 180);
            color: rgba(220, 220, 220, 220);
            border: 1px solid rgba(100, 150, 200, 40);
            border-radius: 6px;
        }
        QPushButton {
            background-color: rgba(60, 90, 130, 180);
            color: rgba(255, 255, 255, 235);
            border: 1px solid rgba(100, 150, 200, 50);
            border-radius: 6px;
            padding: 5px 10px;
        }
        QPushButton:hover {
            background-color: rgba(80, 120, 170, 200);
            color: rgba(255, 255, 255, 235);
        }
        QPushButton:disabled {
            background-color: rgba(40, 50, 60, 120);
            color: rgba(150, 150, 150, 120);
        }
        QTableWidget {
            background-color: rgba(20, 30, 50, 160);
            color: rgba(220, 220, 220, 220);
            gridline-color: rgba(100, 150, 200, 40);
            border: 1px solid rgba(100, 150, 200, 40);
            border-radius: 6px;
        }
        QTableWidget::item {
            background-color: rgba(20, 30, 50, 130);
            color: rgba(220, 220, 220, 220);
        }
        QTableWidget::item:selected {
            background-color: rgba(0, 120, 212, 150);
            color: rgba(255, 255, 255, 220);
        }
        QGroupBox {
            color: rgba(255, 255, 255, 220);
            border: 1px solid rgba(100, 150, 200, 50);
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
            background: rgba(20, 30, 50, 130);
        }
        QGroupBox::title {
            color: rgba(200, 220, 240, 220);
        }
        QLabel {
            color: rgba(220, 220, 220, 220);
        }
        QCheckBox {
            color: rgba(220, 220, 220, 220);
        }
        QComboBox {
            background-color: rgba(40, 60, 80, 160);
            color: rgba(220, 220, 220, 220);
            border: 1px solid rgba(100, 150, 200, 40);
            border-radius: 6px;
        }
        QComboBox QAbstractItemView {
            background-color: rgba(30, 45, 65, 180);
            color: rgba(220, 220, 220, 220);
            selection-background-color: rgba(0, 120, 212, 150);
            selection-color: rgba(255, 255, 255, 220);
        }
        QTabWidget::pane {
            border: 1px solid rgba(100, 150, 200, 40);
            background-color: rgba(20, 30, 50, 180);
            border-radius: 8px;
        }
        QTabBar::tab {
            background-color: rgba(40, 60, 80, 130);
            color: rgba(200, 200, 200, 200);
            padding: 8px 15px;
            border: 1px solid rgba(100, 150, 200, 30);
            border-bottom: none;
            border-radius: 5px 5px 0 0;
        }
        QTabBar::tab:selected {
            background-color: rgba(60, 90, 120, 180);
            color: rgba(255, 255, 255, 230);
            border-bottom: 2px solid #0078d4;
        }
        QLineEdit {
            background-color: rgba(40, 60, 80, 160);
            color: rgba(220, 220, 220, 220);
            border: 1px solid rgba(100, 150, 200, 40);
            border-radius: 6px;
        }
        QMenuBar {
            background-color: rgba(30, 45, 65, 130);
            color: rgba(220, 220, 220, 220);
        }
        QMenuBar::item:selected {
            background-color: rgba(60, 90, 120, 160);
            color: rgba(255, 255, 255, 220);
        }
        QMenu {
            background-color: rgba(30, 45, 65, 180);
            color: rgba(220, 220, 220, 220);
            border: 1px solid rgba(100, 150, 200, 30);
        }
        QMenu::item:selected {
            background-color: rgba(0, 120, 212, 150);
            color: rgba(255, 255, 255, 220);
        }
        QStatusBar {
            background-color: rgba(15, 25, 45, 130);
            color: rgba(200, 200, 200, 200);
        }
        QDialog {
            background-color: rgba(20, 30, 50, 230);
            color: rgba(220, 220, 220, 220);
        }
        QMessageBox {
            background-color: rgba(20, 30, 50, 230);
            color: rgba(220, 220, 220, 220);
        }
        """
        app.setStyleSheet(dark_style)
        print("[主题] 应用深色主题（固定白色文字）")
    else:
        # 浅色主题
        light_style = """
        QTextEdit:read-only {
            background-color: rgba(248, 248, 248, 200);
            color: rgba(50, 50, 50, 200);
        }
        QTableWidget::item:selected {
            background-color: rgba(0, 120, 212, 150);
            color: rgba(255, 255, 255, 220);
        }
        QGroupBox {
            border: 1px solid rgba(208, 208, 208, 180);
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
            background: rgba(255, 255, 255, 160);
            color: rgba(50, 50, 50, 220);
        }
        QGroupBox::title {
            color: rgba(50, 50, 50, 220);
        }
        QLabel {
            color: rgba(50, 50, 50, 200);
        }
        """
        app.setStyleSheet(light_style)
        print("[主题] 应用浅色主题（固定文字）")

def main():
    set_dll_search_path()

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

    app = QApplication(sys.argv)

    theme = get_system_theme()
    apply_theme(app, theme)

    icon_path = get_icon_path()
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

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