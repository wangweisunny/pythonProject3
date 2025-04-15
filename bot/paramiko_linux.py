import paramiko
import socket
import logging

# 配置日志
logging.basicConfig(filename='remote_control.log', level=logging.INFO, format='%(asctime)s - %(message)s')


def connect_ssh(host, username, password):
    """通过SSH连接到远程主机"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, password=password, timeout=5)
        logging.info(f"成功连接到 {host}")
        return client
    except (paramiko.AuthenticationException, socket.error) as e:
        logging.error(f"连接失败: {host} - {e}")
        return None


def execute_command(client, command):
    """在远程主机上执行命令"""
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        if error:
            logging.error(f"命令执行错误: {command} - {error}")
            return error
        logging.info(f"命令执行成功: {command}")
        return output
    except Exception as e:
        logging.error(f"执行命令失败: {command} - {e}")
        return None


def main():
    # 目标主机IP地址
    target_host = "192.168.1.100"
    username = "user"
    password = "password"

    client = connect_ssh(target_host, username, password)
    if not client:
        print(f"无法连接到 {target_host}")
        return

    try:
        # 执行命令
        command = "whoami"
        output = execute_command(client, command)
        print(f"命令输出: {output}")

        # 关闭连接
        client.close()
    except Exception as e:
        logging.error(f"远程控制失败: {e}")


if __name__ == "__main__":
    main()
