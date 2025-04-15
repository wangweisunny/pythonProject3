import socket
import nmap
import csv
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')


def get_local_ip_windows():
    """在Windows上获取本地IP地址"""
    try:
        # 创建一个UDP套接字
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 连接到一个公共DNS服务器（不会发送数据）
        s.connect(("1.1.1.1", 80))
        # 获取本地IP地址
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
        return None


def scan_network(ip_range):
    """扫描局域网内的在线主机"""
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip_range, arguments='-sn')
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        return hosts_list
    except Exception as e:
        logging.error(f"Error scanning network: {e}")
        return []


def main():
    local_ip = get_local_ip_windows()
    if not local_ip:
        print("无法获取本地IP地址")
        return

    # 获取局域网IP范围
    ip_parts = local_ip.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    print(f"开始扫描局域网: {ip_range}")
    hosts = scan_network(ip_range)

    # 将结果写入CSV文件
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"scan_results_{timestamp}.csv"

    with open(csv_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Status"])
        for host, status in hosts:
            writer.writerow([host, status])
            print(f"{host}: {status}")

    print(f"扫描结果已保存到 {csv_filename}")


if __name__ == "__main__":
    main()
