import socket
import struct
import threading
import time
import psutil
import os
import ipaddress
import subprocess
import platform
from colorama import Fore, Style, init

# ===== 配置 =====
SAMPLE_INTERVAL = 2  # 采样间隔
DETECTION_TIMES = 5  # 检测次数
UDP_PORTS_TO_MONITOR = {6672, 61455, 61456, 61457, 61458}  # GTA在线模式端口
TARGET_PROCESS_KEYWORDS = ["GTA5", "GTA5_Enhanced", "RDR2"]  # 目标进程

# 官方服务器配置
TRADE_SERVER_IPS = {"192.81.245.200", "192.81.245.201"}
CLOUD_SAVE_SERVER_IPS = {"192.81.241.171"}
ROCKSTAR_IP_RANGES = ["52.139."]  # Rockstar官方中转服务器网段

init(autoreset=True)


def check_interface_connectivity(interface_name, ip_address):
    """更准确地检查网络接口是否真正连接到网络"""

    # 169.254.x.x 是APIPA地址，表示未获取到DHCP地址
    if ip_address.startswith("169.254."):
        return False, "APIPA地址(未连接)"

    try:
        # 尝试ping一个公共DNS服务器来测试连接性
        if platform.system().lower() == "windows":
            param = "-n"
        else:
            param = "-c"

        # 使用Google DNS进行连接测试
        result = subprocess.run(
            ["ping", param, "1", "8.8.8.8"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0
        )

        # 检查是否有默认网关
        try:
            # 获取接口的网关信息
            for iface, addrs in psutil.net_if_addrs().items():
                if iface == interface_name:
                    for addr in addrs:
                        if hasattr(addr, 'netmask') and addr.netmask:
                            # 如果有子网掩码但不是255.255.255.255，可能已连接
                            if addr.netmask != "255.255.255.255":
                                return True, "已连接"
        except:
            pass

        # 如果有回包，说明确实有连接
        if result.returncode == 0:
            return True, "已连接"
        else:
            return False, "无网络连接"

    except Exception:
        # 如果ping测试失败，回退到psutil的状态
        try:
            stats = psutil.net_if_stats().get(interface_name)
            if stats and stats.isup:
                return True, "接口已启用"
            else:
                return False, "接口未启用"
        except:
            return False, "状态未知"


def is_official_server(ip):
    """检查IP是否为官方服务器"""
    # 检查是否为交易服务器
    if ip in TRADE_SERVER_IPS:
        return True

    # 检查是否为云存档服务器
    if ip in CLOUD_SAVE_SERVER_IPS:
        return True

    # 检查是否为Rockstar官方网段
    for ip_range in ROCKSTAR_IP_RANGES:
        if ip.startswith(ip_range):
            return True

    # 检查是否为Take-Two相关的IP段
    # Take-Two Interactive Software, Inc. 的AS号通常是AS36692
    # 但这里我们主要关注已知的官方IP

    return False


def is_private_ip(ip):
    """检查是否为私有IP地址（局域网IP）"""
    try:
        ip_obj = ipaddress.ip_address(ip)

        # 私有地址范围：
        # 10.0.0.0/8
        # 172.16.0.0/12
        # 192.168.0.0/16
        # 169.254.0.0/16 (APIPA)

        if ip_obj.is_private:
            return True

        # 额外检查一些常见的游戏P2P IP范围
        ip_parts = ip.split('.')

        # 常见家庭网络
        if ip_parts[0] == "192" and ip_parts[1] == "168":
            return True

        # 办公网络
        if ip_parts[0] == "10":
            return True

        # 虚拟局域网
        if ip_parts[0] == "172" and 16 <= int(ip_parts[1]) <= 31:
            return True

        # APIPA地址
        if ip_parts[0] == "169" and ip_parts[1] == "254":
            return True

    except:
        pass

    return False


def analyze_network_interfaces():
    """分析网络接口并分类 - 修正版本"""
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}=== 网络接口分析 ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}正在扫描您的网络接口...{Style.RESET_ALL}")

    interfaces_info = {
        'physical_connected': [],  # 已连接的物理网卡
        'physical_disconnected': [],  # 未连接的物理网卡
        'virtual': [],  # 虚拟网卡
        'other': []  # 其他
    }

    try:
        for name, addrs in psutil.net_if_addrs().items():
            ipv4_addrs = [addr for addr in addrs if addr.family == socket.AF_INET]

            if not ipv4_addrs:
                continue

            # 获取主IPv4地址
            main_addr = ipv4_addrs[0].address

            # 跳过回环地址
            if main_addr.startswith("127."):
                continue

            # 更准确地检查连接状态
            is_connected, status_msg = check_interface_connectivity(name, main_addr)

            # 判断接口类型
            interface_type = classify_interface(name, main_addr)

            # 构建显示字符串
            info_str = f"{name}: {main_addr}"

            # 添加状态标记
            if is_connected:
                info_str += f" {Fore.GREEN}[{status_msg}]{Style.RESET_ALL}"
            else:
                info_str += f" {Fore.RED}[{status_msg}]{Style.RESET_ALL}"

            # 分类存储
            if interface_type == "virtual":
                info_str += f" {Fore.MAGENTA}[虚拟网卡]{Style.RESET_ALL}"
                interfaces_info['virtual'].append((name, main_addr, is_connected))
            elif interface_type == "physical":
                info_str += f" {Fore.BLUE}[物理网卡]{Style.RESET_ALL}"
                if is_connected:
                    interfaces_info['physical_connected'].append((name, main_addr, is_connected))
                else:
                    interfaces_info['physical_disconnected'].append((name, main_addr, is_connected))
            else:
                interfaces_info['other'].append((name, main_addr, is_connected))

            print(f"  {info_str}")

    except Exception as e:
        print(f"{Fore.RED}扫描网络接口时出错: {e}{Style.RESET_ALL}")

    return interfaces_info


def classify_interface(name, ip):
    """分类网络接口 - 修正版本"""
    name_lower = name.lower()

    # 明确的虚拟网卡标识
    virtual_keywords = [
        "virtual", "vpn", "tap", "tunnel", "vmnet", "vmware",
        "virtualbox", "hyper-v", "vethernet", "ppp", "tap-windows",
        "zerotier", "tailscale", "wireguard", "openvpn", "加速器",
        "uu", "雷神", "迅游", "奇游", "netch", "sstap"
    ]

    for keyword in virtual_keywords:
        if keyword in name_lower:
            return "virtual"

    # 明确的物理网卡标识
    physical_keywords = [
        "ethernet", "以太网", "无线", "wifi", "wi-fi", "wlan",
        "本地连接", "realtek", "intel", "broadcom", "qualcomm",
        "atheros", "marvell", "killer", "media", "网络适配器"
    ]

    for keyword in physical_keywords:
        if keyword in name_lower:
            return "physical"

    # 根据IP地址段辅助判断
    ip_parts = ip.split('.')

    # 家庭/办公室网络通常是物理网卡
    if ip_parts[0] == "192" and ip_parts[1] == "168":
        return "physical"
    elif ip_parts[0] == "10":
        return "physical"

    # 172.16-172.31通常是虚拟网络
    elif ip_parts[0] == "172" and 16 <= int(ip_parts[1]) <= 31:
        return "virtual"

    # 169.254是APIPA地址，可能是未连接的物理网卡
    elif ip_parts[0] == "169" and ip_parts[1] == "254":
        # 检查是否是VMware虚拟网卡
        if "vmnet" in name_lower:
            return "virtual"
        return "physical"

    # 其他私有地址
    elif ip_parts[0] == "172" and int(ip_parts[1]) < 16:
        return "physical"
    elif ip_parts[0] == "172" and int(ip_parts[1]) > 31:
        return "physical"

    return "unknown"


def get_user_input(interfaces_info):
    """获取用户输入的网络接口 - 修正版本"""
    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}=== 接口选择 ==={Style.RESET_ALL}")

    # 显示提示信息
    print(f"{Fore.YELLOW}重要提示:{Style.RESET_ALL}")
    print(f"  1. {Fore.GREEN}家庭/办公室网络{Style.RESET_ALL}: 通常是 192.168.x.x 或 10.x.x.x 开头的IP")
    print(f"  2. {Fore.MAGENTA}虚拟网卡{Style.RESET_ALL}: 通常是 172.x.x.x 开头的IP (如UU加速器)")
    print(f"  3. {Fore.RED}APIPA地址{Style.RESET_ALL}: 169.254.x.x 表示未获取到DHCP地址，网络未正常连接")

    # 显示建议的物理网卡（已连接）
    if interfaces_info['physical_connected']:
        print(f"\n{Fore.GREEN}疑似的已连接物理网卡:{Style.RESET_ALL}")
        for name, ip, connected in interfaces_info['physical_connected']:
            status = "✓" if connected else "✗"
            color = Fore.GREEN if connected else Fore.RED
            print(f"  {name}: {ip} {color}[{status}]{Style.RESET_ALL}")

    # 显示虚拟网卡
    if interfaces_info['virtual']:
        print(f"\n{Fore.MAGENTA}疑似的虚拟网卡:{Style.RESET_ALL}")
        for name, ip, connected in interfaces_info['virtual']:
            status = "✓" if connected else "✗"
            color = Fore.GREEN if connected else Fore.RED
            print(f"  {name}: {ip} {color}[{status}]{Style.RESET_ALL}")

    # 显示未连接的物理网卡
    if interfaces_info['physical_disconnected']:
        print(f"\n{Fore.RED}疑似的未连接物理网卡:{Style.RESET_ALL}")
        for name, ip, connected in interfaces_info['physical_disconnected']:
            status = "✓" if connected else "✗"
            color = Fore.GREEN if connected else Fore.RED
            print(f"  {name}: {ip} {color}[{status}]{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}注意:{Style.RESET_ALL}")
    print(f"  ✓ 表示接口有网络连接")
    print(f"  ✗ 表示接口无网络连接或未启用")
    print(f"  APIPA地址(169.254.x.x)通常表示网络未正常连接")

    # 获取用户输入
    print(f"\n{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")

    # 获取物理网卡IP
    while True:
        print(f"\n{Fore.YELLOW}请参考上面的列表选择:{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}请确保在输入前已进入在线模式战局！{Style.RESET_ALL}")
        physical_ip = input(f"{Fore.GREEN}请输入物理网卡的IP地址: {Style.RESET_ALL}").strip()

        if not physical_ip:
            print(f"{Fore.RED}请输入有效的IP地址{Style.RESET_ALL}")
            continue

        # 验证IP格式
        try:
            socket.inet_aton(physical_ip)

            # 检查是否是APIPA地址并提示
            if physical_ip.startswith("169.254."):
                confirm = input(
                    f"{Fore.YELLOW}警告: 您选择了APIPA地址(169.254.x.x)，这通常表示网络未正常连接。是否继续？(y/n): {Style.RESET_ALL}").strip().lower()
                if confirm != 'y':
                    continue

            break
        except socket.error:
            print(f"{Fore.RED}无效的IP地址格式，请重新输入{Style.RESET_ALL}")

    # 获取虚拟网卡IP
    while True:
        virtual_ip = input(f"{Fore.MAGENTA}请输入虚拟网卡的IP地址: {Style.RESET_ALL}").strip()

        if not virtual_ip:
            print(f"{Fore.RED}请输入有效的IP地址{Style.RESET_ALL}")
            continue

        try:
            socket.inet_aton(virtual_ip)

            # 检查是否与物理网卡相同
            if virtual_ip == physical_ip:
                print(f"{Fore.RED}虚拟网卡IP不能与物理网卡IP相同{Style.RESET_ALL}")
                continue

            # 检查是否是APIPA地址并提示
            if virtual_ip.startswith("169.254."):
                confirm = input(
                    f"{Fore.YELLOW}警告: 您选择了APIPA地址(169.254.x.x)，这通常表示网络未正常连接。是否继续？(y/n): {Style.RESET_ALL}").strip().lower()
                if confirm != 'y':
                    continue

            break
        except socket.error:
            print(f"{Fore.RED}无效的IP地址格式，请重新输入{Style.RESET_ALL}")

    return physical_ip, virtual_ip


class UDPDetector:
    """UDP流量检测器 - 过滤官方服务器版本"""

    def __init__(self, interface_ip):
        self.interface_ip = interface_ip
        self.running = False
        self.udp_count = 0
        self.lock = threading.Lock()
        self.gta_ports = set()

    def start(self):
        """开始检测"""
        self.running = True
        self.udp_count = 0

        # 启动端口扫描线程
        port_thread = threading.Thread(target=self._scan_ports, daemon=True)
        port_thread.start()
        time.sleep(1)

        # 启动嗅探线程
        sniff_thread = threading.Thread(target=self._sniffer, daemon=True)
        sniff_thread.start()

    def stop(self):
        """停止检测"""
        self.running = False

    def _scan_ports(self):
        """扫描GTA进程使用的端口"""
        while self.running:
            tmp_ports = set()
            try:
                for proc in psutil.process_iter(['name']):
                    try:
                        if proc.info['name'] and any(x in proc.info['name'] for x in TARGET_PROCESS_KEYWORDS):
                            connections = proc.net_connections(kind='udp')
                            for conn in connections:
                                if conn.laddr:
                                    port = conn.laddr.port
                                    if port in UDP_PORTS_TO_MONITOR:
                                        tmp_ports.add(port)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
            except Exception:
                pass

            all_ports = UDP_PORTS_TO_MONITOR.union(tmp_ports)
            with self.lock:
                self.gta_ports = all_ports

            time.sleep(2)

    def _sniffer(self):
        """UDP数据包嗅探 - 过滤官方服务器流量"""
        try:
            # 创建原始套接字
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            s.bind((self.interface_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Windows下需要特殊设置
            if hasattr(socket, 'SIO_RCVALL') and psutil.WINDOWS:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        except Exception as e:
            print(f"{Fore.RED}接口 {self.interface_ip} 初始化失败: {e}{Style.RESET_ALL}")
            if "管理员" in str(e) or "权限" in str(e):
                print(f"{Fore.YELLOW}提示: 可能需要以管理员权限运行{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}✓ 开始监控接口 {self.interface_ip}{Style.RESET_ALL}")

        while self.running:
            try:
                raw_data = s.recvfrom(65535)[0]

                # 解析IP头部
                ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data[0:20])
                protocol = ip_header[6]

                # 只处理UDP协议
                if protocol != 17:
                    continue

                # 解析UDP头部
                ihl = (ip_header[0] & 0xF) * 4
                udp_header = struct.unpack('!HHHH', raw_data[ihl:ihl + 8])

                src_port = udp_header[0]
                dst_port = udp_header[1]

                # 检查是否为目标端口
                with self.lock:
                    target_ports = self.gta_ports

                if not (src_port in target_ports or dst_port in target_ports):
                    continue

                # 获取源IP和目的IP
                s_ip = socket.inet_ntoa(ip_header[8])
                d_ip = socket.inet_ntoa(ip_header[9])

                # 确定远程IP（排除本地IP）
                if s_ip == self.interface_ip:
                    remote_ip = d_ip
                else:
                    remote_ip = s_ip

                # 过滤条件：排除官方服务器，只保留P2P连接
                # 1. 排除已知的官方服务器IP
                if is_official_server(remote_ip):
                    continue

                # 2. 排除私有IP（本地网络通信，可能不是P2P游戏连接）
                # if is_private_ip(remote_ip):
                #     continue

                # 3. 排除多播和广播地址
                if remote_ip.startswith(("224.", "239.", "255.")):
                    continue

                # 4. 排除本地IP
                if remote_ip == self.interface_ip:
                    continue

                # 5. 排除保留地址
                if remote_ip.startswith("0."):
                    continue

                # 通过所有过滤条件，认为是P2P游戏连接
                self.udp_count += 1

            except struct.error:
                pass
            except Exception:
                if not self.running:
                    break

    def get_udp_count(self):
        """获取当前UDP计数并重置"""
        with self.lock:
            count = self.udp_count
            self.udp_count = 0
        return count


def main():
    """主函数"""
    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}=== 检测使用路由模式加速 GTA 在线模式 & Red Dead 在线模式 的加速器是否为假加速 ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}版本: 1.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

    # 显示过滤信息
    print(f"{Fore.GREEN}过滤规则:{Style.RESET_ALL}")
    print(f"  1. 排除官方交易服务器: {', '.join(TRADE_SERVER_IPS)}")
    print(f"  2. 排除云存档服务器: {', '.join(CLOUD_SAVE_SERVER_IPS)}")
    print(f"  3. 排除Rockstar官方网段: {ROCKSTAR_IP_RANGES[0]}*.*")
    print(f"  4. 排除多播/广播地址: 224.*.*.*, 239.*.*.*, 255.*.*.*")
    print(f"  5. 只统计P2P游戏连接")

    # 检查管理员权限
    if psutil.WINDOWS:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"\n{Fore.RED}⚠️  警告: 需要以管理员权限运行{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}按 Enter 键继续，或按 Ctrl+C 退出后以管理员身份重新运行{Style.RESET_ALL}")
                input()
        except:
            pass

    # 分析网络接口
    interfaces_info = analyze_network_interfaces()

    # 获取用户输入
    physical_ip, virtual_ip = get_user_input(interfaces_info)

    # 检测加速器
    while True:
        results = detect_accelerator(physical_ip, virtual_ip)

        # 分析结果
        analyze_results(results, physical_ip, virtual_ip)

        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        choice = input(f"{Fore.YELLOW}是否重新检测？(y/n): {Style.RESET_ALL}").strip().lower()

        if choice != 'y':
            break

    print(f"\n{Fore.GREEN}感谢使用！按任意键退出...{Style.RESET_ALL}")
    input()


def detect_accelerator(physical_ip, virtual_ip):
    """检测加速器状态"""
    print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}=== 开始加速器检测 ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}请确保已进入游戏的多人战局！{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}检测将在5秒后开始...{Style.RESET_ALL}")

    time.sleep(5)

    # 创建两个检测器
    physical_detector = UDPDetector(physical_ip)
    virtual_detector = UDPDetector(virtual_ip)

    # 启动检测
    physical_detector.start()
    virtual_detector.start()

    print(f"\n{Fore.GREEN}✓ 开始检测...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}正在进行 {DETECTION_TIMES} 次检测，每次间隔 {SAMPLE_INTERVAL} 秒{Style.RESET_ALL}")

    results = []

    for i in range(DETECTION_TIMES):
        print(f"\n{Fore.CYAN}第 {i + 1}/{DETECTION_TIMES} 次检测:{Style.RESET_ALL}")

        # 等待采样间隔
        time.sleep(SAMPLE_INTERVAL)

        # 获取UDP计数
        physical_count = physical_detector.get_udp_count()
        virtual_count = virtual_detector.get_udp_count()

        print(f"  物理网卡({physical_ip}): {Fore.BLUE}{physical_count}{Style.RESET_ALL} 个P2P连接")
        print(f"  虚拟网卡({virtual_ip}): {Fore.MAGENTA}{virtual_count}{Style.RESET_ALL} 个P2P连接")

        results.append({
            'physical': physical_count,
            'virtual': virtual_count,
            'ratio': virtual_count / (physical_count + 1)  # 避免除零
        })

    # 停止检测
    physical_detector.stop()
    virtual_detector.stop()

    return results


def analyze_results(results, physical_ip, virtual_ip):
    """分析检测结果"""
    print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}=== 检测结果分析 ==={Style.RESET_ALL}")

    # 计算统计信息
    total_physical = sum(r['physical'] for r in results)
    total_virtual = sum(r['virtual'] for r in results)

    avg_physical = total_physical / len(results)
    avg_virtual = total_virtual / len(results)

    print(f"物理网卡({physical_ip}) P2P连接总数: {Fore.BLUE}{total_physical}{Style.RESET_ALL}")
    print(f"虚拟网卡({virtual_ip}) P2P连接总数: {Fore.MAGENTA}{total_virtual}{Style.RESET_ALL}")

    if total_physical > 0:
        ratio = total_virtual / total_physical
        print(f"虚拟/物理网卡比例: {Fore.YELLOW}{ratio:.2f}{Style.RESET_ALL}")
    else:
        print(f"虚拟/物理网卡比例: {Fore.YELLOW}∞ (物理网卡无P2P连接){Style.RESET_ALL}")

    # 判断加速器状态
    if total_virtual == 0 and total_physical == 0:
        print(f"\n{Fore.RED}⚠️  警告: 两个网卡均未检测到P2P游戏连接{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}可能原因:{Style.RESET_ALL}")
        print(f"  1. 游戏未进入在线战局（需要玩家互动的战局）")
        print(f"  2. 战局中没有其他玩家（单人战局）")
        print(f"  3. 选择的IP地址错误")
        print(f"  4. 游戏可能连接官方服务器进行中转，无P2P连接")
        print(f"\n{Fore.YELLOW}建议:{Style.RESET_ALL}")
        print(f"  1. 加入一个有其他玩家的公开战局")
        print(f"  2. 尝试进行需要玩家互动的活动（如任务、竞速等）")

    elif total_virtual > total_physical * 3:  # 虚拟网卡流量是物理的3倍以上
        print(f"\n{Fore.GREEN}✅ 加速器状态: 正常加速{Style.RESET_ALL}")
        print(f"{Fore.GREEN}您的加速器正在正常工作，P2P游戏连接主要通过虚拟网卡传输{Style.RESET_ALL}")
        print(f"{Fore.GREEN}加速器正在有效优化您的游戏连接！{Style.RESET_ALL}")

    elif total_physical > total_virtual * 3:  # 物理网卡流量是虚拟的3倍以上
        print(f"\n{Fore.RED}⚠️  加速器状态: 可能为假加速{Style.RESET_ALL}")
        print(f"{Fore.RED}检测到P2P游戏连接主要通过物理网卡传输，加速器可能未正常工作{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}可能原因:{Style.RESET_ALL}")
        print(f"  1. 加速器未正确设置路由规则")
        print(f"  2. 加速器节点连接问题")
        print(f"  3. 游戏未通过加速器进行在线游玩")
        print(f"\n{Fore.YELLOW}建议操作:{Style.RESET_ALL}")
        print(f"  1. {Fore.YELLOW}重启加速器并重新加速{Style.RESET_ALL}")
        print(f"  2. {Fore.YELLOW}更换加速器节点{Style.RESET_ALL}")
        print(f"  3. {Fore.YELLOW}通过加速器启动游戏{Style.RESET_ALL}")
        print(f"  4. {Fore.YELLOW}重启电脑后重新检测{Style.RESET_ALL}")

    else:  # 流量接近
        print(f"\n{Fore.YELLOW}⚠️  加速器状态: 部分工作或混合模式{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}P2P连接在两个网卡之间分流，加速器可能以混合模式工作{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}可能情况:{Style.RESET_ALL}")
        print(f"  1. 加速器只加速部分连接")
        print(f"  2. 游戏使用混合P2P连接")
        print(f"  3. 网络环境复杂导致分流")
        print(f"\n{Fore.YELLOW}建议:{Style.RESET_ALL}")
        print(f"  1. 尝试在游戏中切换战局")
        print(f"  2. 重启加速器后重新检测")
        print(f"  3. 联系加速器客服咨询路由模式设置")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}程序已退出{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}程序运行出错: {e}{Style.RESET_ALL}")
        input("按任意键退出...")