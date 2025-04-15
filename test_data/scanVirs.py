import os
import yara  # 需要安装 yara-python 库
import hashlib
import re
import csv  # 导入csv模块

# YARA 规则文件路径
YARA_RULES_DIR = "yara_rules"  # 假设 YARA 规则文件存放在这个目录下

# 假设的恶意文件签名库（实际使用时需要一个完整的签名库）
MALICIOUS_SIGNATURES = {
    "eicar_test": "44240A6B6973746572404D414E4941432E434F4D204E4F5420414E2049444541",
    "another_signature": "DEADBEEFCAFE0000BADF00D"
}

# 假设的可疑代码模式（例如 Base64 编码的可疑字符串）
SUSPICIOUS_PATTERNS = [
    r"eval\s*\(\s*base64_decode\s*\(",
    r"system\s*\(\s*[\"']cmd\s*[\"']",
    r"exec\s*\(\s*[\"']curl\s*[\"']"
]

# CSV文件路径
CSV_LOG_FILE = "scan_results.csv"
total_files = 0  # 读取的文件总数
matched_files = 0  # 匹配上的文件个数


def write_to_csv(file_path, alert_type, message, virus_type=None):
    """将扫描结果写入CSV文件"""
    # 检查CSV文件是否存在，如果不存在则创建并写入标题行
    file_exists = os.path.exists(CSV_LOG_FILE)

    with open(CSV_LOG_FILE, mode='a', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)

        # 如果文件不存在，写入标题行
        if not file_exists:
            writer.writerow(["File Path", "Alert Type", "Message", "Virus Type"])

        # 写入扫描结果
        writer.writerow([file_path, alert_type, message, virus_type])


def load_yara_rules():
    """加载 YARA 规则文件"""
    rules = []
    for root, dirs, files in os.walk(YARA_RULES_DIR):
        for file in files:
            print("加载文件为：", file)
            if file.endswith(".yar") or file.endswith(".yara"):
                rule_path = os.path.join(root, file)
                try:
                    rules.append(yara.compile(filepath=rule_path))
                except yara.Error as e:
                    print(f"Error loading YARA rule {rule_path}: {e}")
    return rules


def check_file_hash(file_path, signatures):
    """检查文件的哈希值是否与已知的恶意签名匹配"""
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            file_hash = hashlib.md5(file_data).hexdigest().upper()

            for name, signature in signatures.items():
                if file_hash == signature.lower():
                    return True, f"Found malicious signature: {name}", "Known Malware"
    except Exception as e:
        print(f"Error checking hash for {file_path}: {e}")
    return False, None, None


def check_suspicious_patterns(file_path, patterns):
    """检查文件内容中是否存在可疑的代码模式"""
    try:
        with open(file_path, "rb") as f:
            file_data = f.read().decode("latin-1", errors="ignore")

            for pattern in patterns:
                if re.search(pattern, file_data, re.IGNORECASE):
                    return True, f"Found suspicious pattern matching: {pattern}", "Suspicious Code"
    except Exception as e:
        print(f"Error checking patterns for {file_path}: {e}")
    return False, None, None


def scan_with_yara(file_path, yara_rules):
    """使用 YARA 规则扫描文件"""
    try:
        for rule in yara_rules:
            matches = rule.match(file_path)
            if matches:
                # 根据YARA规则名称判断病毒类型
                virus_type = classify_virus(matches[0].rule)
                return True, f"Found YARA rule match: {matches[0].rule}", virus_type
    except Exception as e:
        print(f"Error scanning with YARA for {file_path}: {e}")
    return False, None, None


def classify_virus(matched_rule):
    """根据匹配的YARA规则名称判断病毒类型"""
    # 这里可以根据YARA规则名称来判断病毒类型
    # 以下是一些示例规则名称与病毒类型的映射
    virus_type_mapping = {
        "ObfuscatedPhp": "Obfuscated PHP WebShell",
        "DodgyPhp": "Suspicious PHP Code",
        "DangerousPhp": "Dangerous PHP Functions",
        "java_cmdshell": "Java Command WebShell",
        "js_cmdshell": "ASPX Command WebShell",
        "cs_cmdshell": "ASPX Command WebShell",
        "reflect_cmdshell": "ASPX Reflection WebShell",
        "aspxspy": "ASPX Complex WebShell",
        "aspxshell": "ASPX Complex WebShell",
        "other_webshell": "Unknown WebShell",
        "NonPrintableChars": "Non-Printable Characters Detected",
        "PasswordProtection": "Password Protection Detected",
        "HiddenInAFile": "Hidden File Detected",
        "CloudFlareBypass": "CloudFlare Bypass Detected",
        "IRC": "IRC Communication Detected",
        "base64": "Base64 Encoded Data Detected",
        "hex": "Hex Encoded Data Detected",
        "strrev": "String Reversal Detected",
        "Hpack": "Hex Pack Detected",
        "SuspiciousEncoding": "Suspicious Encoding Detected",
        "DodgyStrings": "Suspicious Strings Detected",
        "Websites": "Suspicious Websites Detected"
    }

    return virus_type_mapping.get(matched_rule, "Unknown Virus Type")


def scan_file(file_path, yara_rules):
    """扫描单个文件以检测木马程序"""
    global matched_files  # 使用全局变量来跟踪匹配上的文件个数
    try:
        print(f"Scanning file: {file_path}")

        # 检查文件哈希
        is_malicious, message, virus_type = check_file_hash(file_path, MALICIOUS_SIGNATURES)
        if is_malicious:
            write_to_csv(file_path, "ALERT", message, virus_type)  # 写入CSV
            matched_files += 1  # 增加匹配计数
            return True

        # 检查可疑模式
        is_suspicious, message, virus_type = check_suspicious_patterns(file_path, SUSPICIOUS_PATTERNS)
        if is_suspicious:
            write_to_csv(file_path, "WARNING", message, virus_type)  # 写入CSV
            matched_files += 1  # 增加匹配计数
            return True

        # 使用 YARA 规则扫描
        if yara_rules:
            is_malicious, message, virus_type = scan_with_yara(file_path, yara_rules)
            if is_malicious:
                write_to_csv(file_path, "ALERT", message, virus_type)  # 写入CSV
                matched_files += 1  # 增加匹配计数
                return True

        print("No known malicious signatures, suspicious patterns, or YARA rule matches found.")
        return False
    except PermissionError:
        print(f"Permission denied: {file_path}")
        write_to_csv(file_path, "ERROR", "Permission denied", "Permission Error")  # 写入CSV
        return False
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
        write_to_csv(file_path, "ERROR", str(e), "Unknown Error")  # 写入CSV
        return False


def scan_directory(directory_path):
    """扫描指定目录及其子目录中的所有文件"""
    global total_files  # 使用全局变量来跟踪总文件数
    if not os.path.exists(directory_path):
        print(f"Error: Directory {directory_path} does not exist.")
        return

    yara_rules = load_yara_rules()

    # 获取目录中所有文件的总数
    total_files = 0
    for root, dirs, files in os.walk(directory_path):
        total_files += len(files)

    # 打印总文件数
    print(f"Total files to scan: {total_files}")

    # 开始扫描
    matched_files = 0
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if scan_file(file_path, yara_rules):
                matched_files += 1

    # 扫描完成后输出结果
    print(f"Scan completed. Total files scanned: {total_files}, Matched files: {matched_files}")


if __name__ == "__main__":
    directory_path = "test_data"

    if not os.path.exists(directory_path):
        print("Error: Directory does not exist.")
    else:
        if os.path.isdir(directory_path):
            scan_directory(directory_path)
            print("文件夹->", directory_path, "处理已完成。")
        else:
            yara_rules = load_yara_rules()
            scan_file(directory_path, yara_rules)
            print("文件->", directory_path, "处理已完成。")