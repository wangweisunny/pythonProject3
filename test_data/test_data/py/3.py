# 模拟 XOR 加密模式
with open("test_malware_3.bin", "wb") as f:
    # XOR 加密模式
    f.write(b"\x55\x8B\xEC\x83\xEC\x0C\x33\xC0\xE8\x00\x00\x00\x00\x83\xC4\x04")
    # 模拟 API 调用
    f.write(b"\x6A\x00\xE8\x00\x00\x00\x00\x83\xC4\x04")
    # 填充随机数据
    import random
    for _ in range(256):
        f.write(random.choice([b"\x00", b"\xFF", b"\x12", b"\x34", b"\x56", b"\x78", b"\x9A", b"\xBC", b"\xDE"]))