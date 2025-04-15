import os
import sys
import json


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


def scan_directory(directory_path, signatures):
    """
    扫描目录中的所有文件
    :param directory_path: 要扫描的目录路径
    :param signatures: 病毒特征码字典
    """
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            result = scan_file(file_path, signatures)
            print(f"文件: {file_path}")
            print(f"结果: {result}\n")


def generate_test_files(test_dir, signatures):
    """
    生成测试文件，用于验证脚本的正确率
    :param test_dir: 测试文件目录
    :param signatures: 病毒特征码字典
    """
    os.makedirs(test_dir, exist_ok=True)

    # 生成包含病毒特征码的测试文件
    for i, (virus_name, signature) in enumerate(signatures.items()):
        test_file_path = os.path.join(test_dir, f"infected_{i}.bin")
        with open(test_file_path, "wb") as file:
            file.write(b"Normal file content\n")
            file.write(signature)
            file.write(b"\nMore normal content\n")

    # 生成不包含病毒特征码的测试文件
    for i in range(len(signatures)):
        test_file_path = os.path.join(test_dir, f"clean_{i}.bin")
        with open(test_file_path, "wb") as file:
            file.write(b"This is a clean file with no virus signatures.\n")


def test_scanner(test_dir, signatures):
    """
    测试扫描器的正确率
    :param test_dir: 测试文件目录
    :param signatures: 病毒特征码字典
    """
    true_positives = 0
    false_negatives = 0
    true_negatives = 0
    false_positives = 0

    for root, dirs, files in os.walk(test_dir):
        for file in files:
            file_path = os.path.join(root, file)
            result = scan_file(file_path, signatures)

            if "infected" in file:
                if "检测到病毒" in result:
                    true_positives += 1
                else:
                    false_negatives += 1
            else:
                if "未检测到病毒" in result:
                    true_negatives += 1
                else:
                    false_positives += 1

    accuracy = (true_positives + true_negatives) / (true_positives + true_negatives + false_positives + false_negatives)
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0

    print(f"正确率: {accuracy:.2f}")
    print(f"精确率: {precision:.2f}")
    print(f"召回率: {recall:.2f}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: virus_scanner.py <特征码数据库文件> <文件路径或目录路径>")
        sys.exit(1)

    signature_file = sys.argv[1]
    path = sys.argv[2]

    signatures = load_virus_signatures(signature_file)

    if os.path.isfile(path):
        print(f"扫描文件: {path}")
        print(f"结果: {scan_file(path, signatures)}")
    elif os.path.isdir(path):
        print(f"扫描目录: {path}")
        scan_directory(path, signatures)
    else:
        print(f"路径不存在: {path}")