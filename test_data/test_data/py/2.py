# 模拟壳代码特征
with open("test_malware_2.bin", "wb") as f:
    # 壳代码入口
    f.write(b"\x55\x8B\xEC\x83\xEC\x10\x33\xC0\x60")
    # 模拟 API 调用
    f.write(b"\x6A\x00\xE8\x00\x00\x00\x00\x83\xC4\x04")
    # 模拟跳转指令
    f.write(b"\xE8\x00\x00\x00\x00\x83\xC4\x04")
    # 填充随机数据
    import random
    for _ in range(512):
        f.write(random.choice([b"\x00", b"\xFF", b"\x12", b"\x34", b"\x56", b"\x78", b"\x9A", b"\xBC", b"\xDE"]))