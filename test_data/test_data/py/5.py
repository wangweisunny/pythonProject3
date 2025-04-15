# 模拟行为脚本（无害）
with open("test_malware_5.bat", "w") as f:
    f.write("@echo off\n")
    f.write("echo This is a test script\n")
    f.write("echo Simulating malicious behavior...\n")
    f.write("echo Creating a test file...\n")
    f.write("echo Hello, World! > test.txt\n")
    f.write("echo Connecting to a test server...\n")
    f.write("echo This is just a simulation!\n")
    f.write("pause\n")