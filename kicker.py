import socket
import struct
import threading
import time
import psutil
import requests
import os
import sys
import subprocess
from colorama import Fore, Style, init
from collections import defaultdict
import ipaddress

# === 配置 ===
MONITOR_PORTS = {6672, 61455, 61456, 61457, 61458}  # 监控的UDP端口
CHECK_INTERVAL = 30  # 检测间隔30秒
GEO_CACHE_TTL = 3600  # 1小时缓存
BLOCK_DURATION = 30  # 临时阻断时间（秒）

init(autoreset=True)

# 线程锁
data_lock = threading.Lock()
geo_lock = threading.Lock()
block_lock = threading.Lock()

# 存储连接流量
incoming_traffic = defaultdict(int)  # 传入流量 IP -> 字节数
outgoing_traffic = defaultdict(int)  # 传出流量 IP -> 字节数
geo_cache = {}  # IP -> (时间, 是否国内)
blocked_ips = set()  # 被阻断的IP集合（双向阻断）
pending_unblocks = {}  # IP -> 定时器对象
user_response_remember = None  # 记住用户上次的选择 (True/False/None)
running = True
LOCAL_IP = ""
first_run = True  # 标记是否首次运行


def display_all_network_interfaces():
    """显示所有网络接口的IP地址"""
    print(f"\n{Fore.CYAN}=== 本地网络接口信息 ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}以下为您计算机上所有网络接口的IP地址:{Style.RESET_ALL}")

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
            if "Virtual" in name or "VPN" in name or "TAP" in name:
                interface_type = f"{Fore.GREEN}[虚拟网卡]{Style.RESET_ALL}"
            elif "Wireless" in name or "Wi-Fi" in name or "WLAN" in name:
                interface_type = f"{Fore.CYAN}[无线]{Style.RESET_ALL}"
            elif "Ethernet" in name or "以太网" in name:
                interface_type = f"{Fore.BLUE}[有线]{Style.RESET_ALL}"

            print(f"{name:<20} {ip:<20} {netmask:<15} {interface_type}")

        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

        # 修改点：只保留路由模式提示
        print(f"\n{Fore.YELLOW}选择建议:{Style.RESET_ALL}")
        print(f"  1. {Fore.GREEN}路由模式玩家:{Style.RESET_ALL} 选择显示为[虚拟网卡]的IP地址")

    except Exception as e:
        print(f"{Fore.RED}获取网络接口信息失败: {e}{Style.RESET_ALL}")


def safe_input(prompt):
    """安全的输入函数"""
    try:
        if not sys.stdin or sys.stdin.closed:
            return None
        return input(prompt)
    except (EOFError, KeyboardInterrupt, RuntimeError):
        print(f"\n{Fore.YELLOW}输入被中断{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}输入错误: {e}{Style.RESET_ALL}")
        return None


def get_user_input_ip():
    """获取用户输入的IP地址"""
    display_all_network_interfaces()

    print(f"\n{Fore.CYAN}=== IP地址输入 ==={Style.RESET_ALL}")
    # 修改点：只提路由模式
    print(f"{Fore.YELLOW}路由模式玩家请输入虚拟网卡的IP{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}提示: 可以直接按回车使用自动检测的IP{Style.RESET_ALL}")

    # 自动检测可用的IP
    default_ip = ""
    interfaces = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    interfaces.append((name, addr.address))
                    if "Virtual" in name or "VPN" in name or "TAP" in name:
                        default_ip = addr.address
                        break

        if not default_ip and interfaces:
            default_ip = interfaces[0][1]
    except:
        pass

    ip_input = safe_input(f"\n{Fore.GREEN}请输入要监控的本地IP地址 (直接回车使用 {default_ip}): {Style.RESET_ALL}")

    if ip_input is None or ip_input.strip() == "":
        if default_ip:
            print(f"{Fore.YELLOW}使用自动检测的IP: {default_ip}{Style.RESET_ALL}")
            return default_ip
        else:
            print(f"{Fore.RED}无法自动检测IP，使用回环地址{Style.RESET_ALL}")
            return "127.0.0.1"

    ip = ip_input.strip()

    try:
        socket.inet_aton(ip)
        print(f"\n{Fore.GREEN}✓ 已设置监控IP: {ip}{Style.RESET_ALL}")
        return ip
    except socket.error:
        print(f"{Fore.RED}无效的IP地址格式{Style.RESET_ALL}")
        return get_user_input_ip()


def is_public_ip(ip_str):
    """判断是否为公网IP"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False


def is_chinese_ip(ip):
    """判断是否为国内IP"""
    current_time = time.time()

    with geo_lock:
        if ip in geo_cache:
            cache_time, is_chinese = geo_cache[ip]
            if current_time - cache_time < GEO_CACHE_TTL:
                return is_chinese

    try:
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country"
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            d = r.json()
            if d.get('status') == 'success':
                is_chinese = (d.get('country', '') == '中国')
                with geo_lock:
                    geo_cache[ip] = (current_time, is_chinese)
                return is_chinese
    except:
        pass

    return False


def schedule_unblock(ip, delay):
    """安排定时解除IP阻断"""

    def unblock_timer():
        time.sleep(delay)
        unblock_ip(ip)

    # 取消之前的定时器（如果存在）
    with block_lock:
        if ip in pending_unblocks:
            try:
                pending_unblocks[ip].cancel()
            except:
                pass

    # 创建新的定时器
    timer = threading.Timer(delay, unblock_timer)
    timer.daemon = True
    timer.start()

    with block_lock:
        pending_unblocks[ip] = timer


def block_ip(ip, duration=BLOCK_DURATION):
    """临时阻断指定IP的双向UDP连接（指定时间后自动恢复）"""
    # 先检查是否已经阻断
    with block_lock:
        if ip in blocked_ips:
            # 已阻断，延长定时器
            print(f"{Fore.YELLOW}⏱️ {ip} 的阻断时间延长至 {duration}秒后{Style.RESET_ALL}")
            schedule_unblock(ip, duration)
            return True

    success_in = False
    success_out = False
    rule_name_in = f"Block_GTA_UDP_{ip.replace('.', '_')}_IN"
    rule_name_out = f"Block_GTA_UDP_{ip.replace('.', '_')}_OUT"
    ports_str = ",".join(map(str, MONITOR_PORTS))

    try:
        if os.name == 'nt':  # Windows
            # 入站规则
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in protocol=udp localport={ports_str} remoteip={ip} action=block'
            result_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
            if result_in.returncode == 0:
                success_in = True
            else:
                print(f"{Fore.RED}入站规则添加失败: {result_in.stderr}{Style.RESET_ALL}")

            # 出站规则（注意使用 remoteport 指定目标端口）
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out protocol=udp remoteport={ports_str} remoteip={ip} action=block'
            result_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
            if result_out.returncode == 0:
                success_out = True
            else:
                print(f"{Fore.RED}出站规则添加失败: {result_out.stderr}{Style.RESET_ALL}")
        else:  # Linux
            # 入站规则 (INPUT链)
            for port in MONITOR_PORTS:
                cmd_in = f'sudo iptables -A INPUT -p udp --dport {port} -s {ip} -j DROP'
                subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
            success_in = True  # 简化：假设都成功，实际可检查返回值

            # 出站规则 (OUTPUT链)
            for port in MONITOR_PORTS:
                cmd_out = f'sudo iptables -A OUTPUT -p udp --dport {port} -d {ip} -j DROP'
                subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
            success_out = True
    except Exception as e:
        print(f"{Fore.RED}添加防火墙规则时出错: {e}{Style.RESET_ALL}")

    if success_in and success_out:
        with block_lock:
            blocked_ips.add(ip)
        print(f"{Fore.GREEN}✓ 已完全阻断 {ip} 的双向通信 ({duration}秒后自动恢复){Style.RESET_ALL}")
        schedule_unblock(ip, duration)
        return True
    else:
        # 如果只有部分成功，回滚已添加的规则
        if success_in:
            try:
                if os.name == 'nt':
                    subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_in}"', shell=True)
                else:
                    for port in MONITOR_PORTS:
                        subprocess.run(f'sudo iptables -D INPUT -p udp --dport {port} -s {ip} -j DROP', shell=True)
            except:
                pass
        if success_out:
            try:
                if os.name == 'nt':
                    subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_out}"', shell=True)
                else:
                    for port in MONITOR_PORTS:
                        subprocess.run(f'sudo iptables -D OUTPUT -p udp --dport {port} -d {ip} -j DROP', shell=True)
            except:
                pass
        print(f"{Fore.RED}✗ 阻断 {ip} 失败，未添加任何规则{Style.RESET_ALL}")
        return False


def unblock_ip(ip):
    """解除IP的双向阻断"""
    with block_lock:
        if ip not in blocked_ips:
            # 清理定时器
            if ip in pending_unblocks:
                try:
                    pending_unblocks[ip].cancel()
                    del pending_unblocks[ip]
                except:
                    pass
            return

        # 从阻断列表中移除
        blocked_ips.discard(ip)

        # 清理定时器
        if ip in pending_unblocks:
            try:
                pending_unblocks[ip].cancel()
                del pending_unblocks[ip]
            except:
                pass

    rule_name_in = f"Block_GTA_UDP_{ip.replace('.', '_')}_IN"
    rule_name_out = f"Block_GTA_UDP_{ip.replace('.', '_')}_OUT"

    try:
        if os.name == 'nt':  # Windows
            # 删除入站规则
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_in}"', shell=True)
            # 删除出站规则
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_out}"', shell=True)
        else:  # Linux
            for port in MONITOR_PORTS:
                subprocess.run(f'sudo iptables -D INPUT -p udp --dport {port} -s {ip} -j DROP', shell=True)
                subprocess.run(f'sudo iptables -D OUTPUT -p udp --dport {port} -d {ip} -j DROP', shell=True)
        print(f"{Fore.CYAN}↻ {ip} 的双向通信已恢复{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}解除阻断时出错: {e}{Style.RESET_ALL}")


def cleanup_firewall_rules():
    """清理所有创建的防火墙规则"""
    print(f"\n{Fore.YELLOW}正在清理防火墙规则...{Style.RESET_ALL}")

    with block_lock:
        ips_to_unblock = list(blocked_ips)

    for ip in ips_to_unblock:
        unblock_ip(ip)

    print(f"{Fore.GREEN}清理完成{Style.RESET_ALL}")


def sniffer():
    """网络数据包嗅探 - 监控所有GTA端口的传入和传出UDP流量"""
    global running

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.bind((LOCAL_IP, 0))
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
            if iph[6] != 17:  # 只处理UDP
                continue

            ihl = (iph[0] & 0xF) * 4
            udph = struct.unpack('!HHHH', raw[ihl:ihl + 8])

            dst_port = udph[1]
            src_port = udph[0]

            # 监控所有配置端口的连接
            if dst_port not in MONITOR_PORTS and src_port not in MONITOR_PORTS:
                continue

            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            # 跳过广播和多播地址
            if src_ip.startswith(("224.", "239.", "255.")) or dst_ip.startswith(("224.", "239.", "255.")):
                continue

            # 确定远程IP和流量方向
            if dst_ip == LOCAL_IP and src_ip != LOCAL_IP:
                # 传入连接
                remote_ip = src_ip
                # 检查IP是否被阻断（双向阻断）
                with block_lock:
                    if remote_ip in blocked_ips:
                        continue
                with data_lock:
                    incoming_traffic[remote_ip] += len(raw)

            elif src_ip == LOCAL_IP and dst_ip != LOCAL_IP:
                # 传出连接
                remote_ip = dst_ip
                with block_lock:
                    if remote_ip in blocked_ips:
                        continue
                with data_lock:
                    outgoing_traffic[remote_ip] += len(raw)

        except struct.error:
            pass
        except Exception as e:
            if running:
                pass


def clear_screen():
    """清屏函数"""
    os.system('cls' if os.name == 'nt' else 'clear')


def format_speed(bytes_count, interval=CHECK_INTERVAL):
    """格式化速度显示（KB/s）"""
    speed_kb = (bytes_count / interval) / 1024.0
    if speed_kb >= 1024:
        return f"{speed_kb / 1024:.2f} MB/s"
    else:
        return f"{speed_kb:.2f} KB/s"


def monitor():
    """定期显示连接信息并处理用户输入"""
    global user_response_remember, first_run

    last_display_time = 0  # 初始化为0，确保第一次立即执行

    while running:
        current_time = time.time()

        # 首次运行或每30秒执行一次
        if first_run or (current_time - last_display_time) >= CHECK_INTERVAL:
            if first_run:
                first_run = False
            last_display_time = current_time

            # 每次检测前清屏
            clear_screen()

            # 显示标题
            print(f"{Fore.CYAN}{'=' * 85}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   GTA在线模式 裸连玩家临时踢出工具 v4.2 (仅路由模式)   {Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 85}{Style.RESET_ALL}")
            print(
                f"{Fore.GREEN}监控IP: {LOCAL_IP} | 端口: {sorted(MONITOR_PORTS)} | 检测间隔: {CHECK_INTERVAL}秒{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 85}{Style.RESET_ALL}")

            with data_lock:
                # 获取所有传入和传出连接
                incoming_ips = list(incoming_traffic.items())
                outgoing_ips = list(outgoing_traffic.items())
                # 清除旧数据，准备下一个周期
                incoming_traffic.clear()
                outgoing_traffic.clear()

            # 合并所有IP用于后续处理
            all_ips = set()
            ip_data = {}

            for ip, bytes_in in incoming_ips:
                all_ips.add(ip)
                if ip not in ip_data:
                    ip_data[ip] = {'in': 0, 'out': 0}
                ip_data[ip]['in'] = bytes_in

            for ip, bytes_out in outgoing_ips:
                all_ips.add(ip)
                if ip not in ip_data:
                    ip_data[ip] = {'in': 0, 'out': 0}
                ip_data[ip]['out'] = bytes_out

            # 先显示当前活跃连接（IP显示在最上方）
            if ip_data:
                print(f"\n{Fore.CYAN}📡 当前活跃连接 (过去{CHECK_INTERVAL}秒):{Style.RESET_ALL}")
                print(
                    f"{Fore.CYAN}{'IP地址':<20} {'↓ 下载':<12} {'↑ 上传':<12} {'总流量':<12} {'状态'}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'-' * 85}{Style.RESET_ALL}")

                # 按总流量排序显示
                sorted_ips = sorted(ip_data.items(), key=lambda x: x[1]['in'] + x[1]['out'], reverse=True)

                for ip, data in sorted_ips[:15]:  # 最多显示15个
                    bytes_in = data['in']
                    bytes_out = data['out']
                    total_bytes = bytes_in + bytes_out

                    in_speed = format_speed(bytes_in)
                    out_speed = format_speed(bytes_out)
                    total_speed = format_speed(total_bytes)

                    # 判断是否为裸连玩家
                    is_chinese = is_public_ip(ip) and is_chinese_ip(ip)
                    status = "[裸连]" if is_chinese else ""

                    # 判断是否被阻断
                    with block_lock:
                        is_blocked = ip in blocked_ips

                    if is_blocked:
                        ip_color = Fore.MAGENTA
                        status = "[已阻断]"
                    elif is_chinese:
                        ip_color = Fore.YELLOW
                    else:
                        ip_color = Fore.WHITE

                    print(
                        f"{ip_color}{ip:<20}{Style.RESET_ALL} {in_speed:<12} {out_speed:<12} {total_speed:<12} {status}")

                if len(sorted_ips) > 15:
                    print(f"  ... 还有 {len(sorted_ips) - 15} 个连接")
            else:
                print(f"\n{Fore.YELLOW}📡 当前没有检测到网络连接{Style.RESET_ALL}")

            print(f"{Fore.CYAN}{'-' * 85}{Style.RESET_ALL}")

            # 检查裸连玩家（国内IP）- 只检查未被阻断的IP
            chinese_ips = []
            for ip, data in ip_data.items():
                with block_lock:
                    if ip in blocked_ips:
                        continue
                if is_public_ip(ip) and is_chinese_ip(ip):
                    chinese_ips.append((ip, data['in'] + data['out']))

            if chinese_ips:
                print(f"\n{Fore.RED}⚠️ 检测到以下裸连玩家: {Style.RESET_ALL}")
                for i, (ip, total_bytes) in enumerate(chinese_ips, 1):
                    total_speed = format_speed(total_bytes)
                    print(f"  {i}. {Fore.YELLOW}{ip}{Style.RESET_ALL} - 总流量: {total_speed}")

                print(f"\n{Fore.RED}⚠️ 警告: 踢出裸连玩家可能会导致以下情况:{Style.RESET_ALL}")
                print(f"  {Fore.RED}• 若不是战局主机: 自己卡入单人战局或无法踢出 {Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}• 如果是战局主机: 可安全踢出{Style.RESET_ALL}")

                # 根据上次记住的选择处理
                response = None
                if user_response_remember is not None:
                    # 如果有记住的选择，直接使用
                    response = 'y' if user_response_remember else 'n'
                    action = "踢出" if user_response_remember else "跳过"
                    print(f"{Fore.CYAN}↻ 使用上次的选择: {action}{Style.RESET_ALL}")
                else:
                    # 等待用户输入
                    response = safe_input(
                        f"\n{Fore.GREEN}是否临时踢出这些裸连玩家 (30秒后自动恢复)? (y/n/记住此选择输入r): {Style.RESET_ALL}")

                    if response and response.lower() == 'r':
                        # 用户想要记住选择
                        remember_response = safe_input(f"{Fore.YELLOW}请选择要记住的操作 (y/n): {Style.RESET_ALL}")
                        if remember_response and remember_response.lower() == 'y':
                            user_response_remember = True
                            response = 'y'
                            print(f"{Fore.GREEN}✓ 已记住选择: 自动踢出{Style.RESET_ALL}")
                        elif remember_response and remember_response.lower() == 'n':
                            user_response_remember = False
                            response = 'n'
                            print(f"{Fore.GREEN}✓ 已记住选择: 自动跳过{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.YELLOW}输入无效，本次不记住选择{Style.RESET_ALL}")
                            response = None

                if response and response.lower() == 'y':
                    print(f"\n{Fore.YELLOW}正在临时阻断裸连玩家双向连接 (30秒后自动恢复)...{Style.RESET_ALL}")

                    success_count = 0
                    for ip, _ in chinese_ips:
                        if block_ip(ip, BLOCK_DURATION):
                            success_count += 1

                    print(f"\n{Fore.GREEN}✓ 已临时阻断 {success_count}/{len(chinese_ips)} 个裸连玩家{Style.RESET_ALL}")

                    # 如果不是主机，给出警告
                    print(f"{Fore.YELLOW}⚠️ 提示: 如果您不是战局主机，踢出操作可能导致您卡入单人战局或无法踢出{Style.RESET_ALL}")
                elif response and response.lower() == 'n':
                    print(f"{Fore.CYAN}已取消踢出操作{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}当前没有检测到裸连玩家{Style.RESET_ALL}")

            # 显示记住状态
            if user_response_remember is not None:
                action = "自动踢出" if user_response_remember else "自动跳过"
                print(f"\n{Fore.CYAN}当前记住的选择: {action} (输入r可重新设置){Style.RESET_ALL}")

            print(f"\n{Fore.YELLOW}⏱️ 下次检测倒计时: {CHECK_INTERVAL}秒 | 按 Ctrl+C 退出{Style.RESET_ALL}")

        time.sleep(1)  # 每秒检查一次


def main():
    global LOCAL_IP, running, user_response_remember

    # 清屏开始
    clear_screen()

    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}   GTA 在线模式 & Red Dead 在线模式 裸连玩家踢出工具   {Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}监测端口: {sorted(MONITOR_PORTS)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}检测间隔: {CHECK_INTERVAL}秒{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}临时阻断: {BLOCK_DURATION}秒后自动恢复{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}运行模式: 仅支持路由模式{Style.RESET_ALL}")
    print(f"{Fore.RED}⚠️  警告: 踢出功能可能导致卡单人战局    {Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    # 获取用户输入的IP
    LOCAL_IP = get_user_input_ip()

    # 再次清屏
    clear_screen()

    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}   GTA 在线模式 & Red Dead 在线模式 裸连玩家踢出工具   {Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}监测端口: {sorted(MONITOR_PORTS)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}检测间隔: {CHECK_INTERVAL}秒{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}临时阻断: {BLOCK_DURATION}秒后自动恢复{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}运行模式: 仅支持路由模式{Style.RESET_ALL}")
    print(f"{Fore.RED}⚠️  警告: 踢出功能可能导致卡单人战局    {Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    # 询问是否启用记住功能
    remember_choice = safe_input(f"{Fore.YELLOW}是否启用自动记住选择功能？(y/n，默认n): {Style.RESET_ALL}")
    if remember_choice and remember_choice.lower() == 'y':
        default_action = safe_input(f"{Fore.YELLOW}请选择默认操作 (y=自动踢出/n=自动跳过，默认n): {Style.RESET_ALL}")
        if default_action and default_action.lower() == 'y':
            user_response_remember = True
            print(f"{Fore.GREEN}✓ 已设置默认操作: 自动踢出裸连玩家{Style.RESET_ALL}")
        else:
            user_response_remember = False
            print(f"{Fore.GREEN}✓ 已设置默认操作: 自动跳过{Style.RESET_ALL}")
    else:
        user_response_remember = None
        print(f"{Fore.CYAN}未启用自动记住功能，每次检测将手动确认{Style.RESET_ALL}")

    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    # 检查管理员权限
    if psutil.WINDOWS:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"{Fore.RED}错误: 需要管理员权限运行以捕获网络数据包和设置防火墙规则{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}请以管理员身份重新运行此程序{Style.RESET_ALL}")
                input("按回车键退出...")
                return
        except:
            pass

    # 启动工作线程
    threads = []
    sniffer_thread = threading.Thread(target=sniffer, daemon=True)
    sniffer_thread.start()
    threads.append(sniffer_thread)

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    threads.append(monitor_thread)

    print(f"{Fore.GREEN}监控已启动，正在进行首次检测...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    try:
        # 主线程等待
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}收到停止信号，正在关闭...{Style.RESET_ALL}")
    finally:
        running = False
        # 清理防火墙规则
        cleanup_firewall_rules()
        print(f"{Fore.GREEN}程序已退出{Style.RESET_ALL}")


if __name__ == "__main__":
    main()