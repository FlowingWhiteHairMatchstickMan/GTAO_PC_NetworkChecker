import socket
import struct
import threading
import time
import psutil
import requests
import sys
import os
import ipaddress
from ping3 import ping
from colorama import Fore, Style, init
from collections import deque, defaultdict

# === 配置 ===
SAMPLE_INTERVAL = 2
UI_REFRESH_RATE = 10
HISTORY_SIZE = 10
GEO_CACHE_TTL = 3600  # 1小时缓存

# UDP监控端口（GTA在线模式专用）
UDP_PORTS_TO_MONITOR = {6672, 61455, 61456, 61457, 61458}
# ============

init(autoreset=True)
TARGET_PROCESS_KEYWORDS = ["GTA5", "GTA5_Enhanced", "RDR2"]

# 官方服务器配置
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
# 官方中转服务器网段
ROCKSTAR_IP_RANGES = [
    "52.139.",  # Rockstar官方中转服务器网段
]

# 线程锁
data_lock = threading.Lock()
geo_lock = threading.Lock()
dns_lock = threading.Lock()

# 存储UDP流量
raw_bytes_map = defaultdict(int)
geo_cache = {}
dns_cache = {}
gta_ports = set(UDP_PORTS_TO_MONITOR)
running = True
LOCAL_IP = ""


def display_all_network_interfaces():
    """显示所有网络接口的IP地址"""
    print(f"\n{Fore.CYAN}=== 本地网络接口信息 ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}以下为您计算机上所有网络接口的IP地址:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}请根据您的网络模式选择合适的IP:{Style.RESET_ALL}")

    interfaces = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    interfaces.append((name, addr.address, addr.netmask))

        if not interfaces:
            print(f"{Fore.RED}未找到可用的网络接口！{Style.RESET_ALL}")
            return

        # 显示表格
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{'接口名称':<20} {'IP地址':<20} {'子网掩码':<15}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")

        for name, ip, netmask in interfaces:
            interface_type = ""
            if "Virtual" in name or "VPN" in name or "TAP" in name or "Tunnel" in name:
                interface_type = f"{Fore.GREEN}[虚拟网卡]{Style.RESET_ALL}"
            elif "Wireless" in name or "Wi-Fi" in name or "WLAN" in name:
                interface_type = f"{Fore.CYAN}[无线]{Style.RESET_ALL}"
            elif "Ethernet" in name or "以太网" in name:
                interface_type = f"{Fore.BLUE}[有线]{Style.RESET_ALL}"

            print(f"{name:<20} {ip:<20} {netmask:<15} {interface_type}")

        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}选择建议:{Style.RESET_ALL}")
        print(f"  1. {Fore.GREEN}路由模式玩家:{Style.RESET_ALL} 选择显示为[虚拟网卡]的IP地址")
        print(f"  2. {Fore.CYAN}进程模式玩家:{Style.RESET_ALL} 选择显示为[有线]或[无线]的IP地址")
        print(f"  3. {Fore.YELLOW}不确定选哪个?{Style.RESET_ALL} 可以尝试先进入游戏战局，然后查看哪个IP有流量")

    except Exception as e:
        print(f"{Fore.RED}获取网络接口信息失败: {e}{Style.RESET_ALL}")


def safe_input(prompt):
    """安全的输入函数，处理EXE环境下的stdin问题"""
    try:
        # 检查stdin是否可用
        if not sys.stdin or sys.stdin.closed:
            print(f"{Fore.RED}标准输入不可用，使用默认IP{Style.RESET_ALL}")
            return None

        # 尝试获取输入
        return input(prompt)
    except (EOFError, KeyboardInterrupt, RuntimeError):
        # 处理中断或stdin错误
        print(f"\n{Fore.YELLOW}输入被中断，使用默认IP{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}输入错误: {e}{Style.RESET_ALL}")
        return None


def get_user_input_ip():
    """获取用户输入的IP地址"""
    # 先显示所有网络接口
    display_all_network_interfaces()

    print(f"\n{Fore.CYAN}=== IP地址输入 ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}路由模式玩家请输入虚拟网卡的IP{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}进程模式玩家请输入您的物理网卡的IP{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}提示: 可以直接按回车使用自动检测的IP{Style.RESET_ALL}")

    # 自动检测可用的IP
    default_ip = ""
    interfaces = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    interfaces.append((name, addr.address))
                    # 优先选择虚拟网卡或以太网
                    if "Virtual" in name or "VPN" in name or "TAP" in name:
                        default_ip = addr.address
                        break

        if not default_ip and interfaces:
            default_ip = interfaces[0][1]
    except:
        pass

    # 尝试获取用户输入
    ip_input = safe_input(f"\n{Fore.GREEN}请输入要监控的本地IP地址 (直接回车使用 {default_ip}): {Style.RESET_ALL}")

    # 如果用户没有输入或输入被中断，使用默认IP
    if ip_input is None or ip_input.strip() == "":
        if default_ip:
            print(f"{Fore.YELLOW}使用自动检测的IP: {default_ip}{Style.RESET_ALL}")
            return default_ip
        else:
            # 如果没有默认IP，使用回环地址
            print(f"{Fore.RED}无法自动检测IP，使用默认回环地址{Style.RESET_ALL}")
            return "127.0.0.1"

    ip = ip_input.strip()

    # 基本IP格式验证
    try:
        socket.inet_aton(ip)

        # 检查是否为本地/回环地址
        if ip.startswith("127."):
            print(f"{Fore.RED}警告: 您输入的是回环地址(127.x.x.x)，这通常是错误的{Style.RESET_ALL}")
            confirm = safe_input(f"{Fore.YELLOW}是否继续使用此IP? (y/n): {Style.RESET_ALL}")
            if confirm and confirm.lower() != 'y':
                return get_user_input_ip()  # 重新获取输入

        # 显示确认信息
        print(f"\n{Fore.GREEN}✓ 已设置监控IP: {ip}{Style.RESET_ALL}")
        return ip

    except socket.error:
        print(f"{Fore.RED}无效的IP地址格式，请重新输入{Style.RESET_ALL}")
        return get_user_input_ip()  # 重新获取输入


def get_str_width(s):
    """计算字符串显示宽度（中文字符算2个宽度）"""
    width = 0
    for char in s:
        width += 2 if '\u4e00' <= char <= '\u9fff' else 1
    return width


def truncate_mixed_string(text, max_width):
    """截断混合字符串到指定显示宽度"""
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
    """对齐文本到指定宽度"""
    text = str(text)
    w = get_str_width(text)
    if w > width:
        return truncate_mixed_string(text, width - 2)

    if align == 'left':
        return text + " " * (width - w)
    elif align == 'right':
        return " " * (width - w) + text
    else:  # center
        left = (width - w) // 2
        right = width - w - left
        return " " * left + text + " " * right


def mask_ip_for_privacy(ip, is_chinese):
    """为裸连的玩家隐藏IP中间2位以确保隐私"""
    if not is_chinese:
        return ip

    try:
        parts = ip.split('.')
        if len(parts) == 4:
            # 隐藏中间2位：显示为 x.x.*.*
            return f"{parts[0]}.{parts[1]}.*.*"
    except:
        pass
    return ip


def parse_asn_info(asn_str):
    """解析ASN字符串，提取AS号码和名称"""
    if not asn_str:
        return None, None

    parts = asn_str.split(' ', 1)
    if len(parts) == 2:
        as_number = parts[0]
        as_name = parts[1]
        return as_number, as_name
    return None, asn_str


def get_friendly_isp_name(isp_data, org_data, as_data):
    """生成友好的ISP/ASN显示名称"""

    as_number, as_name = parse_asn_info(as_data)

    if as_number and as_name:
        if "Tencent" in as_name:
            simplified = "腾讯"
        elif "Alibaba" in as_name or "Aliyun" in as_name:
            simplified = "阿里云"
        elif "China Telecom" in as_name:
            simplified = "电信"
        elif "China Mobile" in as_name:
            simplified = "移动"
        elif "China Unicom" in as_name:
            simplified = "联通"
        elif "Cloudflare" in as_name:
            simplified = "Cloudflare"
        elif "Google" in as_name:
            simplified = "谷歌"
        elif "Microsoft" in as_name:
            simplified = "微软"
        elif "Amazon" in as_name or "AWS" in as_name:
            simplified = "AWS"
        elif "Take-Two" in as_name or "Take Two" in as_name or "TAKE-TWO" in as_name:
            simplified = "Take-Two"
        elif "Netease" in as_name:
            simplified = "网易云"
        else:
            simplified = truncate_mixed_string(as_name, 20)

        return f"{as_number} ({simplified})"

    if org_data:
        org_lower = org_data.lower()
        if "tencent" in org_lower:
            return "腾讯"
        elif "alibaba" in org_lower or "aliyun" in org_lower:
            return "阿里云"
        elif "china telecom" in org_lower:
            return "电信"
        elif "china mobile" in org_lower:
            return "移动"
        elif "china unicom" in org_lower:
            return "联通"
        elif "take-two" in org_lower or "take two" in org_lower:
            return "Take-Two"
        elif "cloudflare" in org_lower:
            return "Cloudflare"
        elif "google" in org_lower:
            return "谷歌"
        elif "microsoft" in org_lower:
            return "微软"
        elif "amazon" in org_lower or "aws" in org_lower:
            return "亚马逊"
        elif "netease" in org_lower:
            return "网易云"
        return truncate_mixed_string(org_data, 25)

    return truncate_mixed_string(isp_data, 25) if isp_data else "未知"


def is_chinese_ip(ip):
    """判断是否为国内IP"""
    try:
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country"
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            d = r.json()
            if d.get('status') == 'success':
                return d.get('country', '') == '中国'
    except:
        pass
    return False


def is_take_two_ip(asn_info):
    """判断是否为Take-Two官方IP"""
    if not asn_info:
        return False
    asn_info_lower = str(asn_info).lower()
    return "take-two" in asn_info_lower or "take two" in asn_info_lower


def is_rockstar_ip_range(ip):
    """判断IP是否属于Rockstar官方网段"""
    for ip_range in ROCKSTAR_IP_RANGES:
        if ip.startswith(ip_range):
            return True
    return False


def reverse_dns_lookup(ip):
    """反向DNS查询，获取域名"""
    try:
        with dns_lock:
            if ip in dns_cache:
                return dns_cache[ip]

        domain = socket.gethostbyaddr(ip)[0]

        with dns_lock:
            dns_cache[ip] = domain

        return domain
    except:
        return None


def get_rockstar_server_type(ip, domain, asn_info):
    """获取Rockstar服务器类型"""

    if ip in TRADE_SERVER_IPS:
        return "官方-交易服务器"
    elif ip in CLOUD_SAVE_SERVER_IPS:
        return "官方-云存档服务器"

    if domain:
        for rockstar_domain in ROCKSTAR_DOMAINS:
            if rockstar_domain in domain:
                return "官方-CDN服务器与云服务器"

    if is_rockstar_ip_range(ip):
        return "官方-中转服务器"

    if is_take_two_ip(asn_info):
        return "官方-其他服务器"

    return None


def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False


class Peer:
    def __init__(self, ip):
        self.ip = ip
        self.location = "查询中..."
        self.isp = "-"
        self.asn_info = "-"
        self.is_chinese = False
        self.server_type = None
        self.last_total_bytes = 0
        self.last_seen = time.time()
        self.last_geo_update = 0
        self.history = deque(maxlen=HISTORY_SIZE)
        threading.Thread(target=self._fetch_geo, daemon=True).start()

    def _fetch_geo(self):
        """获取地理位置和ASN信息（带缓存）"""
        current_time = time.time()

        if not is_public_ip(self.ip):
            self.location = "区域网"
            self.isp = None
            self.asn_info = None
            self.is_chinese = False
            self.server_type = None
            self.last_geo_update = current_time
            return

        with geo_lock:
            if self.ip in geo_cache:
                cache_time, location, isp, asn_info, is_chinese, server_type = geo_cache[self.ip]
                if current_time - cache_time < GEO_CACHE_TTL:
                    self.location = location
                    self.isp = isp
                    self.asn_info = asn_info
                    self.is_chinese = is_chinese
                    self.server_type = server_type
                    self.last_geo_update = current_time
                    return

        try:
            domain = reverse_dns_lookup(self.ip)

            url = f"http://ip-api.com/json/{self.ip}?lang=zh-CN&fields=status,country,regionName,city,isp,org,as"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                d = r.json()
                if d.get('status') == 'success':
                    country = d.get('country', '')
                    region = d.get('regionName', '')
                    city = d.get('city', '')

                    self.is_chinese = country == '中国'

                    if self.is_chinese:
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

                    friendly_name = get_friendly_isp_name(isp_raw, org_raw, as_raw)

                    self.location = location.strip() or "未知"
                    self.isp = friendly_name
                    self.asn_info = as_raw if as_raw else org_raw if org_raw else isp_raw

                    server_type = get_rockstar_server_type(self.ip, domain, as_raw or org_raw or isp_raw)
                    if server_type:
                        self.server_type = server_type

                    with geo_lock:
                        geo_cache[self.ip] = (current_time, self.location, self.isp, self.asn_info,
                                              self.is_chinese, self.server_type)

                    self.last_geo_update = current_time
                    return

        except requests.exceptions.Timeout:
            self.location = "查询超时"
            self.isp = "网络错误"
        except Exception as e:
            self.location = "查询失败"
            self.isp = f"错误: {str(e)[:20]}"

        time.sleep(2)
        self.location = "查询重试中..."
        self.isp = "查询重试中..."
        threading.Thread(target=self._fetch_geo, daemon=True).start()
        # with geo_lock:
        #    geo_cache[self.ip] = (current_time, self.location, self.isp, self.asn_info,
        #                          self.is_chinese, self.server_type)

    def record_sample(self, current_total_bytes):
        """记录网络采样数据"""
        if self.last_total_bytes == 0:
            delta = 0
        else:
            delta = current_total_bytes - self.last_total_bytes

        if delta < 0:
            delta = 0

        self.last_total_bytes = current_total_bytes
        if delta > 0:
            self.last_seen = time.time()

        speed = (delta / SAMPLE_INTERVAL) / 1024.0

        latency = None
        if speed > 0.1:
            try:
                rtt = ping(self.ip, unit='ms', timeout=0.5)
                latency = int(rtt) if rtt is not None else None
            except:
                latency = None

        self.history.append((speed, latency))

    def get_summary(self):
        """获取统计摘要"""
        if not self.history:
            return None

        speeds = [x[0] for x in self.history]
        latencies = [x[1] for x in self.history if x[1] is not None]

        avg_speed = sum(speeds) / len(speeds) if speeds else 0
        max_speed = max(speeds) if speeds else 0
        avg_lat = sum(latencies) / len(latencies) if latencies else None

        time_since_seen = time.time() - self.last_seen
        is_alive = time_since_seen < (SAMPLE_INTERVAL * HISTORY_SIZE * 1.5)

        # 恢复原始的卡逼判断规则：只根据速度阈值
        is_lagger = avg_speed > 100 or max_speed > 100

        return {
            'avg_speed': avg_speed,
            'max_speed': max_speed,
            'avg_lat': avg_lat,
            'is_alive': is_alive,
            'last_seen_sec': int(time_since_seen),
            'is_lagger': is_lagger
        }


# === 核心逻辑 ===
peers_map = {}


def sniffer():
    """网络数据包嗅探 - 仅UDP"""
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
        print(f"{Fore.RED}嗅探器初始化失败: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}请确保以管理员权限运行{Style.RESET_ALL}")
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

        except struct.error:
            pass
        except Exception as e:
            if running:
                pass


def sampler():
    """定期采样数据"""
    while running:
        time.sleep(SAMPLE_INTERVAL)

        with data_lock:
            current_ips = list(raw_bytes_map.keys())

        for ip in current_ips:
            if ip not in peers_map:
                peers_map[ip] = Peer(ip)
                print(f"{Fore.GREEN}检测到新连接: {ip}{Style.RESET_ALL}")

        for ip, peer in list(peers_map.items()):
            with data_lock:
                current_total = raw_bytes_map.get(ip, 0)

            peer.record_sample(current_total)

            stats = peer.get_summary()
            if stats and not stats['is_alive']:
                with data_lock:
                    if ip in peers_map:
                        print(f"{Fore.YELLOW}连接超时移除: {ip}{Style.RESET_ALL}")
                        del peers_map[ip]
                    if ip in raw_bytes_map:
                        del raw_bytes_map[ip]


def port_scanner():
    """扫描GTA5进程端口"""
    global gta_ports
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
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            if running:
                pass

        all_ports = UDP_PORTS_TO_MONITOR.union(tmp)

        if all_ports != gta_ports:
            gta_ports = all_ports
            if gta_ports:
                print(f"{Fore.CYAN}监控UDP端口: {sorted(gta_ports)}{Style.RESET_ALL}")

        time.sleep(5)


def cleanup():
    """清理资源"""
    global running
    running = False

    with data_lock:
        peers_map.clear()
        raw_bytes_map.clear()
        gta_ports.clear()

    print(f"{Fore.YELLOW}监控已停止{Style.RESET_ALL}")


def main():
    global LOCAL_IP

    # 清屏开始
    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{Fore.CYAN}=== GTA 在线模式 & Red Dead 在线模式 战局网络监测工具 ==={Style.RESET_ALL}")

    # 获取用户输入的IP
    try:
        LOCAL_IP = get_user_input_ip()
    except Exception as e:
        print(f"{Fore.RED}获取IP失败: {e}{Style.RESET_ALL}")
        # 尝试自动获取IP
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        LOCAL_IP = addr.address
                        print(f"{Fore.YELLOW}自动选择IP: {LOCAL_IP}{Style.RESET_ALL}")
                        break
                if LOCAL_IP:
                    break
        except:
            LOCAL_IP = "127.0.0.1"
            print(f"{Fore.RED}使用默认IP: {LOCAL_IP}{Style.RESET_ALL}")

    # 清屏显示配置信息
    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{Fore.CYAN}=== GTA 在线模式 & Red Dead 在线模式 战局网络监测工具 ==={Style.RESET_ALL}")
    print(f"{Fore.RED}⚠️  连接状况仅供参考，请根据实际情况自行判断{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

    # 显示官方服务器配置信息
    print(f"{Fore.GREEN}官方服务器配置:{Style.RESET_ALL}")
    print(f"  交易服务器: {', '.join(TRADE_SERVER_IPS)}")
    print(f"  云存档服务器: {', '.join(CLOUD_SAVE_SERVER_IPS)}")
    print(f"  官方中转网段: 52.139.*.*")

    print(f"\n{Fore.YELLOW}监控本地IP: {LOCAL_IP}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}采样间隔: {SAMPLE_INTERVAL}s | 刷新率: {UI_REFRESH_RATE}s{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}目标进程: {TARGET_PROCESS_KEYWORDS}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}隐私保护: 国内玩家IP显示为 X.X.*.* 格式{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}UDP监控端口: {sorted(UDP_PORTS_TO_MONITOR)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

    # 检查管理员权限
    if psutil.WINDOWS:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"{Fore.RED}警告: 可能需要管理员权限运行以捕获原始套接字{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}如果监控不到流量，请尝试以管理员身份重新运行{Style.RESET_ALL}")
        except:
            pass

    # 启动工作线程
    threads = []
    for func in [sniffer, sampler, port_scanner]:
        t = threading.Thread(target=func, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.1)

    print(f"{Fore.GREEN}监控已启动...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}按 Ctrl+C 停止监控{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

    try:
        last_refresh = time.time()
        refresh_count = 0

        while True:
            current_time = time.time()
            time_to_wait = max(1, UI_REFRESH_RATE - (current_time - last_refresh))

            for i in range(int(time_to_wait), 0, -1):
                sys.stdout.write(
                    f"\r{Fore.YELLOW}⏱️ 刷新倒计时 {i}s | 活跃连接: {len(peers_map)} | UDP端口: {len(gta_ports)} | 按Ctrl+C退出...")
                sys.stdout.flush()
                time.sleep(1)

            last_refresh = time.time()
            refresh_count += 1

            os.system('cls' if os.name == 'nt' else 'clear')

            print(f"{Fore.CYAN}=== GTA 在线模式 & Red Dead 在线模式 战局网络监测工具 ==={Style.RESET_ALL}")
            print(f"{Fore.RED}⚠️  连接状况仅供参考，请根据实际情况自行判断{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

            print(f"{Fore.YELLOW}监控IP: {LOCAL_IP} | 刷新次数: {refresh_count}{Style.RESET_ALL}")
            print(
                f"{Fore.YELLOW}活跃连接数: {len(peers_map)} | UDP端口: {sorted(gta_ports) if gta_ports else '等待游戏进程...'}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 130}{Style.RESET_ALL}")

            rows = []
            with data_lock:
                for peer in list(peers_map.values()):
                    stats = peer.get_summary()
                    if not stats:
                        continue
                    rows.append({'peer': peer, 'stats': stats})

            rows.sort(key=lambda x: x['stats']['avg_speed'], reverse=True)

            header = (
                f"{pad_text('状态', 4)} | "
                f"{pad_text('IP地址', 15)} | "
                f"{pad_text('地区', 57)} | "
                f"{pad_text('均速', 4)} | "
                f"{pad_text('峰值', 4)} | "
                f"{pad_text('延迟', 4)} | "
                f"{pad_text('ASN/运营商', 22)}"
            )
            print(Style.BRIGHT + header + Style.RESET_ALL)
            print(f"{Fore.CYAN}{'-' * 130}{Style.RESET_ALL}")

            if not rows:
                print(f"\n{Fore.YELLOW}暂无活跃连接，等待游戏网络流量...{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}请确保游戏正在运行且已进入在线战局{Style.RESET_ALL}")
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

                    if not s['is_alive']:
                        row_color = Fore.RED
                        status_indicator = "💀"
                    elif s['last_seen_sec'] > SAMPLE_INTERVAL * 5:
                        row_color = Fore.YELLOW
                        status_indicator = "🏁"
                    elif s['avg_speed'] > 10:
                        row_color = Fore.GREEN
                        status_indicator = "🚀"
                    elif s['avg_speed'] > 3:
                        row_color = Fore.CYAN
                        status_indicator = "📡"
                    else:
                        row_color = Fore.WHITE
                        status_indicator = "📶"

                    if p.server_type and "官方" in p.server_type:
                        if "交易" in p.server_type:
                            row_color = Fore.MAGENTA
                        elif "云存档" in p.server_type:
                            row_color = Fore.LIGHTMAGENTA_EX
                        elif "CDN" in p.server_type:
                            row_color = Fore.LIGHTCYAN_EX
                        elif "中转" in p.server_type:
                            row_color = Fore.LIGHTRED_EX
                        else:
                            row_color = Fore.LIGHTYELLOW_EX

                    if p.location == "区域网":
                        row_color = Style.DIM

                    # === 修复卡逼显示问题的关键部分 ===
                    # 先准备纯数值字符串（不带颜色）
                    spd_str_raw = f"{s['avg_speed']:.1f}"
                    max_str_raw = f"{s['max_speed']:.1f}"

                    # 如果是卡逼，只在数值前添加红色标记，但保持数值完整
                    if s['is_lagger']:
                        spd_str = f"{Fore.RED}{spd_str_raw}{Style.RESET_ALL}"
                        max_str = f"{Fore.RED}{max_str_raw}{Style.RESET_ALL}"
                    else:
                        spd_str = spd_str_raw
                        max_str = max_str_raw

                    lat_str = f"{int(s['avg_lat'])}" if s['avg_lat'] else "N/A"

                    # 准备各列数据（使用原始字符串进行宽度计算）
                    col_status = pad_text(f"{status_indicator}", 3, 'center')
                    display_ip = mask_ip_for_privacy(p.ip, p.is_chinese)
                    col_ip = pad_text(display_ip, 15)
                    col_loc = pad_text(location_display, 57)

                    # 重要：pad_text函数应该传入纯文本，而不是带颜色的文本
                    # 但为了显示颜色，我们需要在pad_text之后应用颜色
                    col_spd_pure = pad_text(spd_str_raw, 4, 'right')
                    col_max_pure = pad_text(max_str_raw, 4, 'right')

                    # 重新应用颜色（如果是卡逼）
                    if s['is_lagger']:
                        col_spd = f"{Fore.RED}{col_spd_pure}{Style.RESET_ALL}"
                        col_max = f"{Fore.RED}{col_max_pure}{Style.RESET_ALL}"
                    else:
                        col_spd = col_spd_pure
                        col_max = col_max_pure

                    col_lat = pad_text(lat_str, 4, 'right')
                    col_isp = pad_text(p.isp, 22)

                    # 打印行，使用row_color作为基础颜色，但速度列的颜色已经单独处理
                    print(
                        f"{row_color}{col_status} | "
                        f"{col_ip} | "
                        f"{col_loc} | "
                        f"{Style.BRIGHT}{col_spd}{Style.NORMAL} | "
                        f"{Style.DIM}{col_max}{Style.NORMAL} | "
                        f"{col_lat} | "
                        f"{Style.DIM}{col_isp}{Style.RESET_ALL}"
                    )

            print(f"\n{Fore.CYAN}{'=' * 130}{Style.RESET_ALL}")
            print(f"{Style.DIM}状态: 💀断线 🏁空闲 🚀活跃 📡正常 📶低速 | 速度单位: KB/s | 延迟单位: ms{Style.RESET_ALL}")
            print(
                f"{Style.DIM}提示: [裸连]国内IP (IP隐私保护) | [官方-*]服务器类型 | [疑似卡逼]速度>100KB/s{Style.RESET_ALL}")
            print(f"{Style.DIM}服务器: 紫色=交易 亮紫=云存档 亮青=CDN 亮红=中转 亮黄=其他官方{Style.RESET_ALL}")
            print(f"{Style.DIM}地理: 国内[省份城市] 国外[国家 地区] | ASN: AS号码(运营商简名){Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
            print(f"{Fore.RED}⚠️  连接状况仅供参考，请根据实际情况自行判断{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}\n收到停止信号，正在关闭监控...{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}程序运行错误: {e}{Style.RESET_ALL}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()