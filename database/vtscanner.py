import os
import json
import sys
import csv


def load_virus_signatures(signature_file):
    """
    从外部文件加载病毒特征码数据库
    :param signature_file: 特征码数据库文件路径
    :return: 病毒特征码字典
    """
    try:
        with open(signature_file, "r") as file:
            signatures = json.load(file)
            # 将特征码从十六进制字符串转换为字节
            for virus_name, signature in signatures.items():
                signatures[virus_name] = bytes.fromhex(signature)
            return signatures
    except Exception as e:
        print(f"加载特征码数据库失败: {e}")
        sys.exit(1)


def scan_file(file_path, signatures):
    """
    扫描文件是否包含病毒特征码
    :param file_path: 要扫描的文件路径
    :param signatures: 病毒特征码字典
    :return: 检测结果
    """
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()
            for virus_name, signature in signatures.items():
                if signature in file_content:
                    return f"检测到病毒: {virus_name}"
            return "未检测到病毒"
    except Exception as e:
        return f"扫描失败: {e}"


def scan_directory(directory_path, signatures, output_file):
    """
    扫描目录中的所有文件
    :param directory_path: 要扫描的目录路径
    :param signatures: 病毒特征码字典
    :param output_file: 输出CSV文件路径
    """
    with open(output_file, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["文件路径", "扫描结果"])

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                result = scan_file(file_path, signatures)
                writer.writerow([file_path, result])
                print(f"文件: {file_path}")
                print(f"结果: {result}\n")


def main():
    if len(sys.argv) < 4:
        print("用法: python virus_scanner.py <特征码数据库文件> <文件或目录路径> <输出CSV文件>")
        sys.exit(1)

    signature_file = sys.argv[1]
    path = sys.argv[2]
    output_file = sys.argv[3]

    signatures = load_virus_signatures(signature_file)

    if os.path.isfile(path):
        result = scan_file(path, signatures)
        with open(output_file, "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["文件路径", "扫描结果"])
            writer.writerow([path, result])
        print(f"文件: {path}")
        print(f"结果: {result}")
    elif os.path.isdir(path):
        scan_directory(path, signatures, output_file)
    else:
        print(f"路径不存在: {path}")


if __name__ == "__main__":
    main()