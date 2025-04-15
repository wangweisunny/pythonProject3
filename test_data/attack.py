import os
import time
import random
import socket
import subprocess

def simulate_lateral_movement(source_dir, target_dir, c2_server="127.0.0.1", c2_port=4444):
    """
    模拟横向移动攻击，将恶意文件从源目录复制到目标目录，并尝试与 C2 服务器通信。
    """
    # 确保目录存在
    os.makedirs(target_dir, exist_ok=True)

    # 复制恶意文件
    for file_name in os.listdir(source_dir):
        source_path = os.path.join(source_dir, file_name)
        target_path = os.path.join(target_dir, file_name)
        os.system(f"copy {source_path} {target_path}")

    # 模拟与 C2 服务器的通信
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((c2_server, c2_port))
        sock.send(b"CHECKIN")
        response = sock.recv(1024)
        print(f"C2 Server Response: {response.decode()}")
        sock.close()
    except Exception as e:
        print(f"C2 Communication Error: {e}")

    # 模拟进程注入
    try:
        subprocess.Popen(["notepad.exe", target_path], shell=True)
    except Exception as e:
        print(f"Process Injection Error: {e}")

# 使用示例
if __name__ == "__main__":
    source_dir = "test_data/malicious"
    target_dir = "compromised"
    c2_server = "127.0.0.1"
    c2_port = 4444

    simulate_lateral_movement(source_dir, target_dir, c2_server, c2_port)
    print(f"Simulated lateral movement from {source_dir} to {target_dir}")