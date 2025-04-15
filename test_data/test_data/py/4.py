# 模拟 API 调用模式
with open("test_malware_4.bin", "wb") as f:
    # API 调用模式
    f.write(b"\x6A\x00\xE8\x00\x00\x00\x00\x83\xC4\x04")
    # 模拟壳代码
    f.write(b"\x55\x8B\xEC\x83\xEC\x10\x33\xC0\x60")
    # 填充随机数据
    import random
    for _ in range(1024):
        f.write(random.choice([b"\x00", b"\xFF", b"\x12", b"\x34", b"\x56", b"\x78", b"\x9A", b"\xBC", b"\xDE"]))