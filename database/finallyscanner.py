import os
import json
import sys
import csv
import hashlib
import requests
import threading
from datetime import datetime


class VirusScanner:
    def __init__(self, signature_dir, cloud_api_key=None):
        self.signatures = self.load_virus_signatures(signature_dir)
        self.cloud_api_key = cloud_api_key
        self.last_update_time = None

    def load_virus_signatures(self, signature_dir):
        """
        从目录中的所有特征码数据库文件加载病毒特征码
        :param signature_dir: 特征码数据库文件目录
        :return: 病毒特征码字典
        """
        signatures = {}
        try:
            if not os.path.exists(signature_dir):
                print(f"特征码目录不存在: {signature_dir}")
                sys.exit(1)

            for file_name in os.listdir(signature_dir):
                file_path = os.path.join(signature_dir, file_name)
                if os.path.isfile(file_path) and file_name.endswith('.json'):
                    with open(file_path, "r") as file:
                        file_signatures = json.load(file)
                        # 将特征码从十六进制字符串转换为字节
                        for virus_name, signature in file_signatures.items():
                            signatures[virus_name] = bytes.fromhex(signature)
            return signatures
        except Exception as e:
            print(f"加载特征码数据库失败: {e}")
            sys.exit(1)

    def update_signatures(self, signature_dir):
        """
        更新病毒特征码数据库
        :param signature_dir: 特征码数据库文件目录
        """
        try:
            current_time = datetime.now()
            if self.last_update_time is None or (current_time - self.last_update_time).total_seconds() > 3600:
                self.signatures = self.load_virus_signatures(signature_dir)
                self.last_update_time = current_time
                print("特征码数据库已更新")
        except Exception as e:
            print(f"更新特征码数据库失败: {e}")

    def scan_file(self, file_path):
        """
        扫描文件是否包含病毒特征码
        :param file_path: 要扫描的文件路径
        :return: 检测结果
        """
        try:
            with open(file_path, "rb") as file:
                file_content = file.read()
                # 特征码检测
                for virus_name, signature in self.signatures.items():
                    if signature in file_content:
                        return f"检测有病毒: {virus_name}"

                # 启发式分析
                if self.heuristic_analysis(file_content):
                    return "检测到可疑行为"

                # 云查杀
                if self.cloud_api_key:
                    if self.cloud_lookup(file_content):
                        return "云查杀检测到病毒"

                return "未检测到病毒"
        except Exception as e:
            return f"扫描失败: {e}"

    def heuristic_analysis(self, file_content):
        """
        启发式分析，检查文件行为模式
        :param file_content: 文件内容
        :return: 是否检测到可疑行为
        """
        # 示例启发式规则：检查文件是否包含大量无意义的NOP指令
        nop_count = file_content.count(b'\x90')
        if nop_count > 100:
            return True
        return False

    def cloud_lookup(self, file_content):
        """
        使用云查杀API检查文件
        :param file_content: 文件内容
        :return: 是否检测到病毒
        """
        try:
            file_hash = hashlib.md5(file_content).hexdigest()
            headers = {
                "Authorization": f"Bearer {self.cloud_api_key}"
            }
            response = requests.get(f"https://api.example.com/virustotal/file/{file_hash}", headers=headers)
            if response.status_code == 200 and response.json().get("positives", 0) > 0:
                return True
            return False
        except Exception as e:
            print(f"云查杀失败: {e}")
            return False

    def scan_directory(self, directory_path, output_file):
        """
        扫描目录中的所有文件
        :param directory_path: 要扫描的目录路径
        :param output_file: 输出CSV文件路径
        """
        total_files = 0
        infected_files = 0

        with open(output_file, "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["文件路径", "扫描结果", "扫描时间"])

            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    total_files += 1
                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path)
                    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    writer.writerow([file_path, result, scan_time])
                    print(f"文件: {file_path}")
                    print(f"结果: {result}")
                    print(f"时间: {scan_time}\n")

                    if "检测有病毒" in result or "检测到可疑行为" in result or "云查杀检测到病毒" in result:
                        infected_files += 1

        print(f"扫描完成！总文件数: {total_files}, 病毒感染文件数: {infected_files}")

    def main(self, signature_dir, path, output_file):
        self.update_signatures(signature_dir)

        if os.path.isfile(path):
            result = self.scan_file(path)
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(output_file, "w", newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["文件路径", "扫描结果", "扫描时间"])
                writer.writerow([path, result, scan_time])
            print(f"文件: {path}")
            print(f"结果: {result}")
            print(f"时间: {scan_time}")
        elif os.path.isdir(path):
            self.scan_directory(path, output_file)
        else:
            print(f"路径不存在: {path}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("用法: python virus_scanner.py <特征码数据库目录> <文件或目录路径> <输出CSV文件> [云API密钥]")
        sys.exit(1)

    signature_dir = sys.argv[1]
    path = sys.argv[2]
    output_file = sys.argv[3]
    cloud_api_key = sys.argv[4] if len(sys.argv) > 4 else None

    scanner = VirusScanner(signature_dir, cloud_api_key)
    scanner.main(signature_dir, path, output_file)