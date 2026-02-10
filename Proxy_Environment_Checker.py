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

    # 判断加速器状态 - 修改后的逻辑
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

    elif total_virtual > 0 and total_physical > 0:
        # 物理网卡和虚拟网卡同时有流量 - 警告加速可能失效
        print(f"\n{Fore.YELLOW}⚠️  注意：加速器加速可能已失效{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}检测到P2P游戏连接同时出现在物理网卡和虚拟网卡上{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}这表示游戏流量未被完全接管，加速器可能未正常工作{Style.RESET_ALL}")

        # 根据流量比例给出更详细的分析
        if total_virtual > total_physical * 2:
            print(f"\n{Fore.YELLOW}流量分析: 虚拟网卡流量占优 ({total_virtual} vs {total_physical}){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}加速器部分工作，但仍有流量直连{Style.RESET_ALL}")
        elif total_physical > total_virtual * 2:
            print(f"\n{Fore.YELLOW}流量分析: 物理网卡流量占优 ({total_physical} vs {total_virtual}){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}大部分流量未经过加速器{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}流量分析: 两个网卡流量相当 ({total_physical} vs {total_virtual}){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}流量严重分流，加速器未完全接管{Style.RESET_ALL}")

        print(f"\n{Fore.RED}【必须执行的操作】{Style.RESET_ALL}")
        print(f"{Fore.RED}请按顺序尝试以下解决方案：{Style.RESET_ALL}")
        print(f"  {Fore.RED}1️⃣  完全退出游戏和加速器{Style.RESET_ALL}")
        print(f"  {Fore.RED}2️⃣  重启加速器并重新加速游戏{Style.RESET_ALL}")
        print(f"  {Fore.RED}3️⃣  通过加速器启动游戏（而非先开游戏后开加速器）{Style.RESET_ALL}")
        print(f"  {Fore.RED}4️⃣  如果问题依旧，尝试更换加速器节点{Style.RESET_ALL}")
        print(f"  {Fore.RED}5️⃣  重启电脑后重新检测{Style.RESET_ALL}")
        print(f"  {Fore.RED}6️⃣  联系加速器客服，确认是否支持路由模式，或切换为进程模式{Style.RESET_ALL}")

    elif total_virtual > total_physical * 3:  # 虚拟网卡流量是物理的3倍以上
        print(f"\n{Fore.GREEN}✅ 加速器状态: 正常加速{Style.RESET_ALL}")
        print(f"{Fore.GREEN}您的加速器正在正常工作，P2P游戏连接主要通过虚拟网卡传输{Style.RESET_ALL}")
        print(f"{Fore.GREEN}加速器正在有效优化您的游戏连接！{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}温馨提示:{Style.RESET_ALL}")
        print(f"  如果遇到延迟波动，可以尝试更换节点")

    elif total_physical > total_virtual * 3:  # 物理网卡流量是虚拟的3倍以上
        print(f"\n{Fore.RED}⚠️⚠️⚠️  加速器状态: 可能为假加速 ⚠️⚠️⚠️{Style.RESET_ALL}")
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