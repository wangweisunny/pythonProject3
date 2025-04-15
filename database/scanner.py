import os
import json
import sys
import subprocess


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


def test_scanner(test_dir, signatures, scanner_script, output_file):
    """
    测试扫描器的正确率
    :param test_dir: 测试文件目录
    :param signatures: 病毒特征码字典
    :param scanner_script: 主扫描脚本路径
    :param output_file: 输出文件路径
    """
    true_positives = 0
    false_negatives = 0
    true_negatives = 0
    false_positives = 0

    with open(output_file, "w") as f:
        for root, dirs, files in os.walk(test_dir):
            for file in files:
                file_path = os.path.join(root, file)

                # 运行主扫描脚本
                command = f"python {scanner_script} {signature_file} {file_path}"
                result = subprocess.check_output(command, shell=True).decode("utf-8").strip()

                f.write(f"文件: {file_path}\n")
                f.write(f"结果: {result}\n\n")

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

        # 计算正确率、精确率和召回率
        total_tests = true_positives + true_negatives + false_positives + false_negatives
        if total_tests == 0:
            accuracy = 0
        else:
            accuracy = (true_positives + true_negatives) / total_tests

        if (true_positives + false_positives) == 0:
            precision = 0
        else:
            precision = true_positives / (true_positives + false_positives)

        if (true_positives + false_negatives) == 0:
            recall = 0
        else:
            recall = true_positives / (true_positives + false_negatives)

        f.write(f"正确率: {accuracy:.2f}\n")
        f.write(f"精确率: {precision:.2f}\n")
        f.write(f"召回率: {recall:.2f}\n")

        print(f"正确率: {accuracy:.2f}")
        print(f"精确率: {precision:.2f}")
        print(f"召回率: {recall:.2f}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python test_generator.py <特征码数据库文件> <测试目录> [主扫描脚本路径] [输出文件]")
        sys.exit(1)

    signature_file = sys.argv[1]
    test_dir = sys.argv[2]
    scanner_script = sys.argv[3] if len(sys.argv) > 3 else None
    output_file = sys.argv[4] if len(sys.argv) > 4 else "test_results.txt"

    signatures = load_virus_signatures(signature_file)
    generate_test_files(test_dir, signatures)

    if scanner_script:
        test_scanner(test_dir, signatures, scanner_script, output_file)