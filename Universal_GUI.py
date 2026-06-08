#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GTA5/RDR2 网络监控工具 - 整合命令行抓包核心 + GUI 功能
"""

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
from collections import deque, defaultdict

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QLabel, QMessageBox, QHeaderView,
                             QTabWidget, QGroupBox, QFormLayout, QLineEdit,
                             QTextEdit, QInputDialog, QComboBox, QDialog,
                             QDialogButtonBox, QCheckBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QSettings
from PyQt5.QtGui import QColor, QBrush, QFont, QIcon

# ====================== 路径辅助函数 ======================
def get_base_path():
    """获取程序所在目录（兼容开发环境和打包后的exe）"""
    if getattr(sys, 'frozen', False):
        # 打包后的 exe 运行
        return os.path.dirname(sys.executable)
    else:
        # 开发环境运行
        return os.path.dirname(os.path.abspath(__file__))


def get_icon_path():
    """获取图标文件路径（兼容打包）"""
    # 使用你实际打包时指定的图标文件名
    icon_filename = "ad8886a276923f717c5abf11f10228ee_256x256.ico"

    if getattr(sys, 'frozen', False):
        # 打包后的 exe 运行
        if hasattr(sys, '_MEIPASS'):
            base = sys._MEIPASS
        else:
            base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, icon_filename)

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
            udph = struct.unpack('!HHHH', raw[ihl:ihl+8])
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

# ====================== 按需阻断管理器 ======================
class OnDemandBlocker:
    def __init__(self):
        self.blocked_ips = set()
        self.temp_blocked = {}
        self.filter = None
        self.running = False
        self.thread = None
        self.lock = threading.Lock()

    def _ensure_running(self):
        with self.lock:
            if self.running:
                return
            self.running = True
            self.thread = threading.Thread(target=self._filter_loop, daemon=True)
            self.thread.start()

    def _filter_loop(self):
        try:
            import pydivert
            port_list = ' or '.join(f'udp.DstPort == {p}' for p in UDP_PORTS_TO_MONITOR)
            filter_str = f"({port_list}) and ip"
            self.filter = pydivert.WinDivert(filter_str)
            self.filter.open()
        except Exception as e:
            print(f"启动阻断过滤器失败: {e}")
            self.running = False
            return
        while self.running:
            now = time.time()
            with self.lock:
                for ip in list(self.temp_blocked.keys()):
                    if now >= self.temp_blocked[ip]:
                        del self.temp_blocked[ip]
            with self.lock:
                has_block = bool(self.blocked_ips or self.temp_blocked)
            if not has_block:
                time.sleep(1)
                continue
            try:
                packet = self.filter.recv(timeout_ms=100)
                if packet is None:
                    continue
                src_ip = packet.src_addr
                with self.lock:
                    if src_ip in self.blocked_ips or src_ip in self.temp_blocked:
                        continue
                self.filter.send(packet)
            except Exception:
                pass
        if self.filter:
            try:
                self.filter.close()
            except:
                pass

    def block_ip(self, ip, permanent=True, duration_sec=30):
        with self.lock:
            if permanent:
                self.blocked_ips.add(ip)
            else:
                self.temp_blocked[ip] = time.time() + duration_sec
        self._ensure_running()

    def unblock_ip(self, ip):
        with self.lock:
            self.blocked_ips.discard(ip)
            if ip in self.temp_blocked:
                del self.temp_blocked[ip]

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
        self.running = False
        if self.filter:
            try:
                self.filter.close()
            except:
                pass

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

    def run(self):
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
            with pydivert.WinDivert(filter_str) as w:
                start_time = time.time()
                for packet in w:
                    if time.time() - start_time > 10:
                        break
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
                    for r in ROCKSTAR_IP_RANGES:
                        if remote.startswith(r):
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
            self.output.emit("")
            self.output.emit("=" * 70)
            self.output.emit("检测结果")
            self.output.emit("=" * 70)
            self.output.emit(f"物理网卡({self.phy_ip}) 检测到 {len(phy_packets)} 个P2P连接")
            self.output.emit(f"虚拟网卡({self.virt_ip}) 检测到 {len(virt_packets)} 个P2P连接")
            self.output.emit("")
            if len(virt_packets) == 0 and len(phy_packets) == 0:
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
            self.solo_process.join()
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
            self.locked_process.join()
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
        self.log_text.setMaximumHeight(150)
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
            self.solo_status_label.setStyleSheet("color: red;")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 卡单人战局已停止")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

    def start_locked_session(self):
        success, msg = self.session_manager.start_locked_session()
        if success:
            self.locked_status_label.setText("运行中")
            self.locked_status_label.setStyleSheet("color: green;")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 战局锁已启动")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

    def stop_locked_session(self):
        success, msg = self.session_manager.stop_locked_session()
        if success:
            self.locked_status_label.setText("未启动")
            self.locked_status_label.setStyleSheet("color: red;")
            self.log_text.append(f"[{time.strftime('%H:%M:%S')}] 战局锁已停止")
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "警告", msg)

# ====================== 主窗口 ======================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GTA 在线模式 & Red Dead 在线模式 战局管理工具")
        self.resize(1400, 850)

        # 设置窗口图标
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # 选择本地IP
        global LOCAL_IP
        LOCAL_IP = self.get_user_input_ip()
        if not LOCAL_IP:
            QMessageBox.critical(self, "错误", "未选择有效IP，程序退出")
            sys.exit(1)
        # 初始化黑名单（使用正确的路径）
        self.base_path = get_base_path()
        self.blacklist_file = os.path.join(self.base_path, "permanent_blacklist.txt")
        self.permanent_blacklist = set()
        self.load_blacklist()

        # 启动抓包线程
        threading.Thread(target=sniffer, daemon=True).start()
        threading.Thread(target=sampler, daemon=True).start()
        threading.Thread(target=port_scanner, daemon=True).start()

        # 阻断器
        self.blocker = OnDemandBlocker()
        for ip in self.permanent_blacklist:
            self.blocker.block_ip(ip, permanent=True)

        # 进程监控
        self.proc_monitor = ProcessMonitorThread()
        self.proc_monitor.process_exited.connect(self.on_process_exited)
        self.proc_monitor.start()

        # 界面
        self.setup_ui()

        # 定时刷新显示
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_display)
        self.refresh_timer.start(UI_REFRESH_RATE * 1000)

        # 阻断列表定时器
        self.block_timer = QTimer()
        self.block_timer.timeout.connect(self.update_block_table)
        self.block_timer.start(1000)
        self.crash_detection_enabled = False
        self.show_private_ip = False

    def on_temp_block_ip(self):
        ip, ok = QInputDialog.getText(self, "临时阻断IP", "请输入要临时阻断的IP地址（30秒后自动解除）:")
        if ok and ip:
            try:
                socket.inet_aton(ip)
                self.blocker.block_ip(ip, permanent=False, duration_sec=30)
                self.update_block_table()
                QMessageBox.information(self, "成功", f"已临时阻断IP {ip}，30秒后将自动解除")
            except socket.error:
                QMessageBox.warning(self, "错误", "无效的IP地址格式")

    def get_user_input_ip(self):
        # 使用本地 INI 文件存储配置（位于程序目录）
        config_file = os.path.join(get_base_path(), "config.ini")
        settings = QSettings(config_file, QSettings.IniFormat)
        remember = settings.value("RememberIP", False, type=bool)
        last_ip = settings.value("LastSelectedIP", "", type=str)

        # 获取当前所有可用IP
        current_ips = []
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    current_ips.append(addr.address)

        # 如果设置了“记住”且上次IP有效，则直接使用
        if remember and last_ip and last_ip in current_ips:
            print(f"使用上次选择的 IP: {last_ip}")
            return last_ip

        # 弹出对话框
        dialog = QDialog(self)
        dialog.setWindowTitle("选择监控的本地IP")
        dialog.setModal(True)
        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        dialog.setWindowFlags(dialog.windowFlags() | Qt.WindowStaysOnTopHint)

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

        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.setFont(font)
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)

        if dialog.exec_() == QDialog.Accepted:
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
        self.monitor_tab = QWidget()
        self.acc_tab = QWidget()
        self.session_tab = SessionControlTab(self)

        layout = QVBoxLayout(self.monitor_tab)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        self.console.setStyleSheet("background-color: white; color: black;")
        layout.addWidget(self.console)

        btn_layout = QHBoxLayout()
        self.crash_btn = QPushButton("挂逼崩溃战局检测")
        self.crash_btn.setCheckable(True)
        self.crash_btn.toggled.connect(self.on_crash_detection_toggled)
        self.refresh_geo_btn = QPushButton("重试未知地理位置")
        self.refresh_geo_btn.clicked.connect(self.on_refresh_geo)
        btn_layout.addWidget(self.crash_btn)
        btn_layout.addWidget(self.refresh_geo_btn)

        tip = QLabel("卡逼判定：平均速率>100KB/s 或 峰值>100KB/s")
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
        self.block_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
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
        self.blacklist_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.refresh_blacklist_table()
        blacklist_layout.addWidget(self.blacklist_table)

        bl_btn_layout = QHBoxLayout()
        add_bl_btn = QPushButton("添加IP到黑名单")
        add_bl_btn.clicked.connect(self.on_add_to_blacklist)
        remove_bl_btn = QPushButton("从黑名单移除")
        remove_bl_btn.clicked.connect(self.on_remove_from_blacklist)
        bl_btn_layout.addWidget(add_bl_btn)
        bl_btn_layout.addWidget(remove_bl_btn)
        blacklist_layout.addLayout(bl_btn_layout)
        right_layout.addWidget(blacklist_group)

        return right_widget

    def setup_accelerator_tab(self):
        layout = QVBoxLayout(self.acc_tab)

        tip_label = QLabel("注意：此检测功能仅适用于“路由模式”的加速器。\n"
                           "如果您使用进程模式加速，将无法检测。")
        tip_label.setWordWrap(True)
        tip_label.setStyleSheet("color: orange; background-color: #FFF3CD; border: 1px solid #FFEEBA; padding: 5px;")
        layout.addWidget(tip_label)

        info_group = QGroupBox("当前网络接口信息")
        info_layout = QVBoxLayout(info_group)
        self.nic_table = QTableWidget()
        self.nic_table.setColumnCount(3)
        self.nic_table.setHorizontalHeaderLabels(["接口名称", "IP地址", "类型"])
        self.nic_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.refresh_nic_table()
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
        self.acc_output.setMinimumHeight(250)
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

    # ------------------- 槽函数 -------------------
    def on_blacklist_toggled(self, checked):
        if checked:
            for ip in self.permanent_blacklist:
                self.blocker.block_ip(ip, permanent=True)
            QMessageBox.information(self, "黑名单", f"已启用黑名单，共 {len(self.permanent_blacklist)} 个IP被永久阻断")
        else:
            for ip in list(self.permanent_blacklist):
                self.blocker.unblock_ip(ip)
            QMessageBox.information(self, "黑名单", "已禁用黑名单，所有IP已解除阻断")

    def on_add_to_blacklist(self):
        ip, ok = QInputDialog.getText(self, "添加IP", "请输入要拉黑的IP地址:")
        if ok and ip:
            try:
                socket.inet_aton(ip)
                self.permanent_blacklist.add(ip)
                self.save_blacklist()
                self.refresh_blacklist_table()
                if self.blacklist_enabled.isChecked():
                    self.blocker.block_ip(ip, permanent=True)
                self.status_label.setText(f"监控IP: {LOCAL_IP} | 端口: {sorted(UDP_PORTS_TO_MONITOR)} | 临时阻断: 0 | 永久黑名单: {len(self.permanent_blacklist)}")
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
            self.status_label.setText(f"监控IP: {LOCAL_IP} | 端口: {sorted(UDP_PORTS_TO_MONITOR)} | 临时阻断: 0 | 永久黑名单: {len(self.permanent_blacklist)}")
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
            reply = QMessageBox.question(self, "检测到新IP", msg + "\n\n是否将这些IP添加到黑名单？",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                for ip in recent_ips:
                    self.permanent_blacklist.add(ip)
                self.save_blacklist()
                self.refresh_blacklist_table()
                if self.blacklist_enabled.isChecked():
                    for ip in recent_ips:
                        self.blocker.block_ip(ip, permanent=True)
                QMessageBox.information(self, "成功", f"已将 {len(recent_ips)} 个IP添加到黑名单")

    def on_show_private_changed(self, state):
        self.show_private_ip = (state == Qt.Checked)
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
        phy_ip = self.phy_ip_edit.text().strip()
        virt_ip = self.virt_ip_edit.text().strip()
        if not phy_ip or not virt_ip:
            QMessageBox.warning(self, "警告", "请填写物理网卡IP和虚拟网卡IP")
            return
        self.acc_output.clear()
        self.detect_btn.setEnabled(False)
        self.acc_test_thread = AcceleratorTestThread(phy_ip, virt_ip)
        self.acc_test_thread.output.connect(self.acc_output.append)
        self.acc_test_thread.finished_signal.connect(lambda: self.detect_btn.setEnabled(True))
        self.acc_test_thread.start()

    def closeEvent(self, event):
        global running
        running = False
        self.proc_monitor.stop()
        self.blocker.stop()
        event.accept()


def main():
    if sys.platform == "win32":
        import ctypes
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                QMessageBox.critical(None, "错误", "请以管理员身份运行！")
                sys.exit(1)
        except:
            pass
    app = QApplication(sys.argv)

    # 设置应用程序图标（影响任务栏和标题栏）
    icon_path = get_icon_path()
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    # 设置应用程序用户模型 ID（确保任务栏图标正确显示）
    if sys.platform == "win32":
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("GTA5_RDR2_Network_Monitor")

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()