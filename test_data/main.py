import yara
from sandbox import CuckooSandbox
from network_analyzer import NetworkAnalyzer
from threat_intel import ThreatIntel


class TrojanDetectionSystem:
    def __init__(self):
        self.sandbox = CuckooSandbox()
        self.network_analyzer = NetworkAnalyzer()
        self.threat_intel = ThreatIntel()
        self.yara_rules = yara.compile("rules.yar")

    def scan_file(self, file_path):
        # 静态分析
        matches = self.yara_rules.match(file_path)
        if matches:
            return {"status": "malicious", "reason": "YARA match", "details": matches}

        # 动态分析
        sandbox_result = self.sandbox.analyze(file_path)
        if sandbox_result.get("malicious"):
            return {"status": "malicious", "reason": "Sandbox detection", "details": sandbox_result}

        # 威胁情报比对
        file_hash = self._get_file_hash(file_path)
        intel_result = self.threat_intel.check_hash(file_hash)
        if intel_result.get("malicious"):
            return {"status": "malicious", "reason": "Threat intelligence", "details": intel_result}

        return {"status": "clean"}

    def monitor_network(self):
        # 网络流量分析
        anomalies = self.network_analyzer.detect_anomalies()
        if anomalies:
            return {"status": "suspicious", "reason": "Network anomalies", "details": anomalies}
        return {"status": "clean"}

    def _get_file_hash(self, file_path):
        # 计算文件哈希值
        import hashlib
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            sha256.update(f.read())
        return sha256.hexdigest()


# 使用示例
if __name__ == "__main__":
    system = TrojanDetectionSystem()

    # 扫描文件
    file_path = "/path/to/suspicious_file.exe"
    result = system.scan_file(file_path)
    print(f"File {file_path} scan result:", result)

    # 监控网络
    network_result = system.monitor_network()
    print("Network monitoring result:", network_result)