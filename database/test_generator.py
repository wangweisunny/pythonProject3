import os
import json
import sys
import random


def load_virus_signatures(signature_dir):
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


def generate_test_files(test_dir, signatures):
    """
    生成测试文件，用于验证脚本的正确率
    :param test_dir: 测试文件目录
    :param signatures: 病毒特征码字典
    """
    os.makedirs(test_dir, exist_ok=True)

    file_types = [".bin", ".txt", ".exe", ".pdf", ".docx"]

    # 生成包含病毒特征码的测试文件
    for i in range(500):  # 生成100个包含病毒特征码的文件
        virus_name, signature = random.choice(list(signatures.items()))
        file_type = random.choice(file_types)
        test_file_path = os.path.join(test_dir, f"infected_{i}{file_type}")
        with open(test_file_path, "wb") as file:
            file.write(b"Normal file content\n")
            file.write(signature)
            file.write(b"\nMore normal content\n")

    # 生成不包含病毒特征码的测试文件
    for i in range(500):  # 生成100个不包含病毒特征码的文件
        file_type = random.choice(file_types)
        test_file_path = os.path.join(test_dir, f"clean_{i}{file_type}")
        with open(test_file_path, "wb") as file:
            file.write(b"This is a clean file with no virus signatures.\n")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python test_generator.py <特征码数据库目录> <测试目录>")
        sys.exit(1)

    signature_dir = sys.argv[1]
    test_dir = sys.argv[2]

    signatures = load_virus_signatures(signature_dir)
    generate_test_files(test_dir, signatures)