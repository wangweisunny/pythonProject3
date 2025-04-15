import os
import yara  # 需要安装 yara-python 库
import hashlib
import re

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


def load_yara_rules():
    """加载 YARA 规则文件"""
    rules = []
    for root, dirs, files in os.walk(YARA_RULES_DIR):
        for file in files:
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
                    return True, f"Found malicious signature: {name}"
    except Exception as e:
        print(f"Error checking hash: {e}")
    return False, None


def check_suspicious_patterns(file_path, patterns):
    """检查文件内容中是否存在可疑的代码模式"""
    try:
        with open(file_path, "rb") as f:
            file_data = f.read().decode("latin-1", errors="ignore")

            for pattern in patterns:
                if re.search(pattern, file_data, re.IGNORECASE):
                    return True, f"Found suspicious pattern matching: {pattern}"
    except Exception as e:
        print(f"Error checking patterns: {e}")
    return False, None


def scan_with_yara(file_path, yara_rules):
    """使用 YARA 规则扫描文件"""
    try:
        for rule in yara_rules:
            matches = rule.match(file_path)
            if matches:
                return True, f"Found YARA rule match: {matches[0].rule}"
    except Exception as e:
        print(f"Error scanning with YARA: {e}")
    return False, None


def scan_file(file_path):
    """扫描文件以检测木马程序"""
    print(f"Scanning file: {file_path}")

    # 加载 YARA 规则
    yara_rules = load_yara_rules()

    # 检查文件哈希
    is_malicious, message = check_file_hash(file_path, MALICIOUS_SIGNATURES)
    if is_malicious:
        print(f"ALERT: {message}")
        return True

    # 检查可疑模式
    is_suspicious, message = check_suspicious_patterns(file_path, SUSPICIOUS_PATTERNS)
    if is_suspicious:
        print(f"WARNING: {message}")
        return True

    # 使用 YARA 规则扫描
    if yara_rules:
        is_malicious, message = scan_with_yara(file_path, yara_rules)
        if is_malicious:
            print(f"ALERT: {message}")
            return True

    print("No known malicious signatures, suspicious patterns, or YARA rule matches found.")
    return False


if __name__ == "__main__":
    file_path = "test_data/aitest/1.jsp"

    if not os.path.exists(file_path):
        print("Error: File does not exist.")
    else:
        scan_file(file_path)