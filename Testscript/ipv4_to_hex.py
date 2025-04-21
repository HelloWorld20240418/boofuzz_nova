
ip = "192.168.1.1"
result = [f"0x{int(part):02X}" for part in ip.split('.')]
print(result)
