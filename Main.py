import socket
import struct
import threading
import time
import psutil
import requests
import sys
from ping3 import ping
from colorama import Fore, Style, init
from collections import deque, defaultdict

# === 配置 ===
LOCAL_IP = "172.19.84.237"
SAMPLE_INTERVAL = 2
UI_REFRESH_RATE = 10
HISTORY_SIZE = 10
GEO_CACHE_TTL = 3600  # 1小时缓存
# ============

init(autoreset=True)
TARGET_PROCESS_KEYWORDS = ["GTA5", "GTA5_Enhanced"]

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
# 新增：Rockstar官方IP网段
ROCKSTAR_IP_RANGES = [
    "52.139.",  # Rockstar官方服务器网段
    "192.81.",  # Rockstar官方服务器网段
]

# 线程锁
data_lock = threading.Lock()
geo_lock = threading.Lock()
dns_lock = threading.Lock()

raw_bytes_map = defaultdict(int)
geo_cache = {}
dns_cache = {}  # 新增：DNS缓存
gta_ports = set()
running = True


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

    # 格式示例: "AS45090 Shenzhen Tencent Computer Systems Company Limited"
    parts = asn_str.split(' ', 1)
    if len(parts) == 2:
        as_number = parts[0]  # AS45090
        as_name = parts[1]  # Shenzhen Tencent...
        return as_number, as_name
    return None, asn_str


def get_friendly_isp_name(isp_data, org_data, as_data):
    """生成友好的ISP/ASN显示名称"""

    as_number, as_name = parse_asn_info(as_data)

    # 优先级：ASN信息 > Org信息 > ISP信息
    if as_number and as_name:
        # 简化的AS名称（去掉冗余的公司后缀）
        if "Tencent" in as_name:
            simplified = "腾讯云"
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
            simplified = "Google"
        elif "Microsoft" in as_name:
            simplified = "微软"
        elif "Amazon" in as_name or "AWS" in as_name:
            simplified = "AWS"
        elif "Take-Two" in as_name or "Take Two" in as_name:
            simplified = "Take-Two"
        else:
            # 取前20个字符
            simplified = truncate_mixed_string(as_name, 20)

        return f"{as_number} ({simplified})"

    # 没有ASN信息，使用org
    if org_data:
        # 尝试简化常见的org名称
        org_lower = org_data.lower()
        if "tencent" in org_lower:
            return "腾讯"
        elif "alibaba" in org_lower or "aliyun" in org_lower:
            return "阿里云"
        elif "china telecom" in org_lower:
            return "中国电信"
        elif "china mobile" in org_lower:
            return "中国移动"
        elif "china unicom" in org_lower:
            return "中国联通"
        elif "take-two" in org_lower or "take two" in org_lower:
            return "Take-Two"
        return truncate_mixed_string(org_data, 25)

    # 最后使用isp
    return truncate_mixed_string(isp_data, 25) if isp_data else "未知"


def is_chinese_ip(ip):
    """判断是否为国内IP"""
    try:
        # 获取IP信息
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
        # 从缓存中查找
        with dns_lock:
            if ip in dns_cache:
                return dns_cache[ip]

        # 执行反向DNS查询
        import socket
        domain = socket.gethostbyaddr(ip)[0]

        # 更新缓存
        with dns_lock:
            dns_cache[ip] = domain

        return domain
    except:
        return None


def get_rockstar_server_type(ip, domain, asn_info):
    """获取Rockstar服务器类型"""

    # 1. 检查特定IP
    if ip in TRADE_SERVER_IPS:
        return "官方-交易服务器"
    elif ip in CLOUD_SAVE_SERVER_IPS:
        return "官方-云存档服务器"

    # 2. 检查域名
    if domain:
        for rockstar_domain in ROCKSTAR_DOMAINS:
            if rockstar_domain in domain:
                return "官方-CDN服务器与云服务器"

    # 3. 检查Rockstar官方IP网段
    if is_rockstar_ip_range(ip):
        return "官方-其他服务器"

    # 4. 检查Take-Two ASN信息
    if is_take_two_ip(asn_info):
        return "官方-其他服务器"

    return None


class Peer:
    def __init__(self, ip):
        self.ip = ip
        self.location = "查询中..."
        self.isp = "-"
        self.asn_info = "-"
        self.is_chinese = False
        self.server_type = None  # 新增：服务器类型
        self.last_total_bytes = 0
        self.last_seen = time.time()
        self.last_geo_update = 0
        self.history = deque(maxlen=HISTORY_SIZE)
        threading.Thread(target=self._fetch_geo, daemon=True).start()

    def _fetch_geo(self):
        """获取地理位置和ASN信息（带缓存）"""
        current_time = time.time()

        # 检查缓存
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
            # 首先进行反向DNS查询
            domain = reverse_dns_lookup(self.ip)

            # 请求字段包含所有需要的信息
            url = f"http://ip-api.com/json/{self.ip}?lang=zh-CN&fields=status,country,regionName,city,isp,org,as"
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                d = r.json()
                if d.get('status') == 'success':
                    # 地理位置
                    country = d.get('country', '')
                    region = d.get('regionName', '')
                    city = d.get('city', '')

                    # 判断是否为国内IP
                    self.is_chinese = country == '中国'

                    # 精简地理位置显示
                    if self.is_chinese:
                        # 国内只显示省份+城市
                        location = f"{region}{city}" if city else region
                    else:
                        # 国外显示国家+地区
                        location_parts = []
                        if country:
                            location_parts.append(country)
                        if region and region != city:  # 避免重复
                            location_parts.append(region)
                        if city:
                            location_parts.append(city)
                        location = " ".join(location_parts[:2])  # 最多显示两部分

                    # ISP/ASN信息处理
                    isp_raw = d.get('isp', '')
                    org_raw = d.get('org', '')
                    as_raw = d.get('as', '')

                    # 生成友好的显示名称
                    friendly_name = get_friendly_isp_name(isp_raw, org_raw, as_raw)

                    self.location = location.strip() or "未知"
                    self.isp = friendly_name
                    self.asn_info = as_raw if as_raw else org_raw if org_raw else isp_raw

                    # 设置服务器类型
                    server_type = get_rockstar_server_type(self.ip, domain, as_raw or org_raw or isp_raw)
                    if server_type:
                        self.server_type = server_type

                    # 更新缓存
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

        # 失败时也更新缓存（短暂缓存失败结果）
        with geo_lock:
            geo_cache[self.ip] = (current_time, self.location, self.isp, self.asn_info,
                                  self.is_chinese, self.server_type)

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

        speed = (delta / SAMPLE_INTERVAL) / 1024.0  # KB/s

        # 测延迟（仅当有流量时）
        latency = None
        if speed > 0.1:  # 有显著流量时才测延迟
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

        # 改进的连接状态判断
        time_since_seen = time.time() - self.last_seen
        is_alive = time_since_seen < (SAMPLE_INTERVAL * HISTORY_SIZE * 1.5)

        # 判断是否为卡逼（速度超过100KB/s）
        is_lagger = avg_speed > 100 or max_speed > 100

        return {
            'avg_speed': avg_speed,
            'max_speed': max_speed,
            'avg_lat': avg_lat,
            'is_alive': is_alive,
            'last_seen_sec': int(time_since_seen),
            'is_lagger': is_lagger  # 新增：是否为卡逼
        }


# === 核心逻辑 ===
peers_map = {}


def sniffer():
    """网络数据包嗅探"""
    try:
        # 解析IP和端口
        if ":" in LOCAL_IP:
            local_ip, local_port = LOCAL_IP.split(":")
            local_port = int(local_port)
        else:
            local_ip = LOCAL_IP
            local_port = 0

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((local_ip, local_port))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if hasattr(socket, 'SIO_RCVALL') and psutil.WINDOWS:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except Exception as e:
        print(f"{Fore.RED}嗅探器初始化失败: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}请确保以管理员/root权限运行{Style.RESET_ALL}")
        return

    while running:
        try:
            raw = s.recvfrom(65535)[0]
            iph = struct.unpack('!BBHHHBBH4s4s', raw[0:20])
            if iph[6] != 17:  # 仅UDP
                continue

            ihl = (iph[0] & 0xF) * 4
            udph = struct.unpack('!HHHH', raw[ihl:ihl + 8])

            # 检查是否为GTA5端口
            src_port = udph[0]
            dst_port = udph[1]
            if not (src_port in gta_ports or dst_port in gta_ports):
                continue

            s_ip = socket.inet_ntoa(iph[8])
            d_ip = socket.inet_ntoa(iph[9])
            remote = d_ip if s_ip == local_ip else s_ip

            # 跳过本地和多播地址
            if remote.startswith(("224.", "239.", "255.")) or remote == local_ip:
                continue

            # 安全写入
            with data_lock:
                raw_bytes_map[remote] += len(raw)

        except struct.error:
            # 数据包格式错误，跳过
            pass
        except Exception as e:
            if running:  # 只在运行时打印错误
                print(f"{Fore.RED}嗅探错误: {e}{Style.RESET_ALL}")
                pass


def sampler():
    """定期采样数据"""
    while running:
        time.sleep(SAMPLE_INTERVAL)

        # 安全获取当前所有IP的快照
        with data_lock:
            current_ips = list(raw_bytes_map.keys())

        # 注册新 Peer
        for ip in current_ips:
            if ip not in peers_map:
                peers_map[ip] = Peer(ip)
                print(f"{Fore.GREEN}检测到新连接: {ip}{Style.RESET_ALL}")

        # 更新数据 & 清理
        for ip, peer in list(peers_map.items()):
            # 安全读取数据
            with data_lock:
                current_total = raw_bytes_map.get(ip, 0)

            peer.record_sample(current_total)

            # 检查是否需要清理（长时间无活动）
            stats = peer.get_summary()
            if stats and not stats['is_alive']:
                with data_lock:
                    if ip in peers_map:
                        print(f"{Fore.YELLOW}连接超时移除: {ip}{Style.RESET_ALL}")
                        del peers_map[ip]
                    if ip in raw_bytes_map:
                        del raw_bytes_map[ip]


def port_scanner():
    """扫描GTA5进程端口 - 修复弃用警告"""
    global gta_ports
    while running:
        tmp = set()
        try:
            for p in psutil.process_iter(['name']):
                try:
                    if p.info['name'] and any(x in p.info['name'] for x in TARGET_PROCESS_KEYWORDS):
                        # 修复: 使用 net_connections() 替代 connections()
                        connections = p.net_connections(kind='udp')
                        for conn in connections:
                            if conn.laddr:
                                tmp.add(conn.laddr.port)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # 进程可能已经结束或无权访问
                    pass
        except Exception as e:
            if running:
                print(f"{Fore.RED}端口扫描错误: {e}{Style.RESET_ALL}")

        if tmp != gta_ports:
            gta_ports = tmp
            if gta_ports:
                print(f"{Fore.CYAN}监控端口更新: {sorted(gta_ports)}{Style.RESET_ALL}")

        time.sleep(5)


def get_network_info():
    """获取网络接口信息"""
    interfaces = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    interfaces.append((name, addr.address))
    except:
        pass
    return interfaces


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
    print(f"{Fore.CYAN}=== GTA5 战局网络监控 (ASN精准识别版) ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}版本: 3.0 | 增加隐私保护 & 网段检测{Style.RESET_ALL}")

    # 显示官方服务器配置信息
    print(f"{Fore.GREEN}官方服务器配置:{Style.RESET_ALL}")
    print(f"  交易服务器: {', '.join(TRADE_SERVER_IPS)}")
    print(f"  云存档服务器: {', '.join(CLOUD_SAVE_SERVER_IPS)}")
    print(f"  Rockstar域名: {len(ROCKSTAR_DOMAINS)}个")
    print(f"  Rockstar网段: {', '.join(ROCKSTAR_IP_RANGES)}")

    # 显示网络接口信息
    interfaces = get_network_info()
    if interfaces:
        print(f"{Fore.GREEN}可用网络接口:{Style.RESET_ALL}")
        for name, ip in interfaces:
            print(f"  {name}: {ip}")

    print(f"{Fore.YELLOW}监控本地IP: {LOCAL_IP}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}采样间隔: {SAMPLE_INTERVAL}s | 刷新率: {UI_REFRESH_RATE}s{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}目标进程: {TARGET_PROCESS_KEYWORDS}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}隐私保护: 国内玩家IP显示为 X.X.*.* 格式{Style.RESET_ALL}")

    # 检查管理员权限
    if psutil.WINDOWS:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"{Fore.RED}警告: 可能需要管理员权限运行以捕获原始套接字{Style.RESET_ALL}")
        except:
            pass

    # 启动工作线程
    threads = []
    for func in [sniffer, sampler, port_scanner]:
        t = threading.Thread(target=func, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.1)  # 稍微错开启动时间

    print(f"{Fore.GREEN}监控已启动...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}按 Ctrl+C 停止监控{Style.RESET_ALL}")

    try:
        last_refresh = time.time()
        while True:
            current_time = time.time()
            time_to_wait = max(1, UI_REFRESH_RATE - (current_time - last_refresh))

            # 显示倒计时
            for i in range(int(time_to_wait), 0, -1):
                sys.stdout.write(
                    f"\r{Fore.YELLOW}⏱️ 刷新倒计时 {i}s | 活跃连接: {len(peers_map)} | 监控端口: {len(gta_ports)} | 按Ctrl+C退出...")
                sys.stdout.flush()
                time.sleep(1)

            last_refresh = time.time()

            # 收集数据
            rows = []
            with data_lock:
                for peer in list(peers_map.values()):
                    stats = peer.get_summary()
                    if not stats:
                        continue
                    rows.append({'peer': peer, 'stats': stats})

            # 按平均速度降序排序
            rows.sort(key=lambda x: x['stats']['avg_speed'], reverse=True)

            # 清屏并显示
            print("\033[2J\033[H")
            print(f"{Fore.CYAN}=== GTA5 战局网络监控 (ASN精准识别版) ==={Style.RESET_ALL}")
            print(
                f"{Fore.YELLOW}活跃连接数: {len(rows)} | 监控端口: {sorted(gta_ports) if gta_ports else '等待GTA5进程...'}{Style.RESET_ALL}")
            print("-" * 140)  # 增加分隔线宽度以适应更宽显示

            # 表头 - 增加各列宽度以容纳更多信息
            header = (
                f"{pad_text('状态', 6)} | "  # 状态列加宽
                f"{pad_text('IP地址', 18)} | "  # IP列加宽
                f"{pad_text('地区', 30)} | "  # 地区列大幅加宽
                f"{pad_text('均速', 12)} | "  # 均速列加宽
                f"{pad_text('峰值', 12)} | "  # 峰值列加宽
                f"{pad_text('延迟', 10)} | "  # 延迟列加宽
                f"{pad_text('ASN/运营商', 45)}"  # ASN列加宽
            )
            print(Style.BRIGHT + header + Style.RESET_ALL)
            print("-" * 140)

            if not rows:
                print(f"{Fore.YELLOW}暂无活跃连接，等待GTA5网络流量...{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}请确保GTA5正在运行且已进入在线战局{Style.RESET_ALL}")
            else:
                for item in rows:
                    p = item['peer']
                    s = item['stats']

                    # 构建地区显示字符串（添加提示）
                    location_display = p.location

                    # 1. 如果是国内IP，添加[裸连]提示
                    if p.is_chinese:
                        location_display += " [裸连]"

                    # 2. 如果有特定服务器类型提示
                    if p.server_type:
                        location_display += f" [{p.server_type}]"

                    # 3. 如果速度超过100KB/s，添加[疑似卡逼]提示
                    if s['is_lagger']:
                        location_display += " [疑似卡逼]"

                    # 确定行颜色和状态指示器
                    if not s['is_alive']:
                        row_color = Fore.RED
                        status_indicator = "💀"
                        status_text = "断线"
                    elif s['last_seen_sec'] > SAMPLE_INTERVAL * 5:
                        row_color = Fore.YELLOW
                        status_indicator = "⚠️"
                        status_text = "空闲"
                    elif s['avg_speed'] > 10:
                        row_color = Fore.GREEN
                        status_indicator = "🚀"
                        status_text = "活跃"
                    elif s['avg_speed'] > 3:
                        row_color = Fore.CYAN
                        status_indicator = "📡"
                        status_text = "正常"
                    else:
                        row_color = Fore.WHITE
                        status_indicator = "📶"
                        status_text = "低速"

                    # 如果是官方服务器，使用特殊颜色
                    if p.server_type and "官方" in p.server_type:
                        if "交易" in p.server_type:
                            row_color = Fore.MAGENTA  # 紫色
                        elif "云存档" in p.server_type:
                            row_color = Fore.LIGHTMAGENTA_EX  # 亮紫色
                        elif "CDN" in p.server_type:
                            row_color = Fore.LIGHTCYAN_EX  # 亮青色
                        else:
                            row_color = Fore.LIGHTYELLOW_EX  # 亮黄色

                    # 格式化数据
                    spd_str = f"{s['avg_speed']:.1f}"
                    max_str = f"{s['max_speed']:.1f}"
                    lat_str = f"{int(s['avg_lat'])}" if s['avg_lat'] else "超时"

                    # 如果速度超过100KB/s，使用红色高亮显示
                    if s['is_lagger']:
                        spd_str = f"{Fore.RED}{s['avg_speed']:.1f}{row_color}"
                        max_str = f"{Fore.RED}{s['max_speed']:.1f}{row_color}"

                    # 对齐列
                    col_status = pad_text(f"{status_indicator}", 6, 'center')
                    # 应用IP隐私保护：国内玩家IP隐藏中间两位
                    display_ip = mask_ip_for_privacy(p.ip, p.is_chinese)
                    col_ip = pad_text(display_ip, 18)
                    col_loc = pad_text(location_display, 30)  # 使用包含提示的字符串
                    col_spd = pad_text(spd_str, 12, 'right')
                    col_max = pad_text(max_str, 12, 'right')
                    col_lat = pad_text(lat_str, 10, 'right')
                    col_isp = pad_text(p.isp, 45)

                    print(
                        f"{row_color}{col_status} | "
                        f"{col_ip} | "
                        f"{col_loc} | "
                        f"{Style.BRIGHT}{col_spd}{Style.NORMAL} | "
                        f"{Style.DIM}{col_max}{Style.NORMAL} | "
                        f"{col_lat} | "
                        f"{Style.DIM}{col_isp}{Style.RESET_ALL}"
                    )

            print("-" * 140)
            print(f"{Style.DIM}状态: 💀断线 ⚠️空闲 🚀活跃 📡正常 📶低速 | 速度单位: KB/s | 延迟单位: ms{Style.RESET_ALL}")
            print(
                f"{Style.DIM}提示: [裸连]国内IP (IP隐私保护) | [官方-*]服务器类型 | [疑似卡逼]速度>100KB/s{Style.RESET_ALL}")
            print(f"{Style.DIM}服务器: 紫色=交易 亮紫=云存档 亮青=CDN 亮黄=其他官方{Style.RESET_ALL}")
            print(f"{Style.DIM}地理: 国内[省份城市] 国外[国家 地区] | ASN: AS号码(运营商简名){Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}\n收到停止信号，正在关闭监控...{Style.RESET_ALL}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()