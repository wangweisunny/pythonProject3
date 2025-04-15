import os
import hashlib
import random
import string
from datetime import datetime

def generate_malicious_sample(file_path, signature="MALICIOUS_SIGNATURE"):
    """
    生成一个带有恶意签名的测试样本文件。
    """
    with open(file_path, "wb") as f:
        # 添加恶意签名
        f.write(signature.encode())
        # 添加随机数据
        random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=1024)).encode()
        f.write(random_data)

def generate_benign_sample(file_path):
    """
    生成一个正常的测试样本文件。
    """
    with open(file_path, "wb") as f:
        # 添加随机数据
        random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=1024)).encode()
        f.write(random_data)

def generate_test_dataset(malicious_dir, benign_dir, num_samples=10):
    """
    生成测试数据集。
    """
    os.makedirs(malicious_dir, exist_ok=True)
    os.makedirs(benign_dir, exist_ok=True)

    # 生成恶意样本
    for i in range(num_samples):
        file_path = os.path.join(malicious_dir, f"malicious_{i}.exe")
        generate_malicious_sample(file_path)

    # 生成正常样本
    for i in range(num_samples):
        file_path = os.path.join(benign_dir, f"benign_{i}.txt")
        generate_benign_sample(file_path)

# 使用示例
if __name__ == "__main__":
    malicious_dir = "test_data/malicious"
    benign_dir = "test_data/benign"
    generate_test_dataset(malicious_dir, benign_dir, num_samples=10)
    print(f"Generated {10} malicious samples in {malicious_dir}")
    print(f"Generated {10} benign samples in {benign_dir}")