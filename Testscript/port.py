import psutil
import socket

# 列出所有网卡及其IP
for interface, addrs in psutil.net_if_addrs().items():
    print(f"网卡: {interface}")
    for addr in addrs:
        if addr.family == socket.AF_INET:
            print(f"  IPv4地址: {addr.address}")

