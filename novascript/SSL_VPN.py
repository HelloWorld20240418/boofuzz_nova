host_ip = ''
host_port = 443

def fuzzing_main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    connection = SSLSocketConnection(host_ip, host_port, sslcontext=context)
    session = Session(target=Target(connection),nova_session_param=nova_session_param )

    # 定义SSL VPN协议基础结构
    def define_vpn_stage(name, static_header, fuzz_part):
        s_initialize(name)
        s_static(static_header)  # 固定协议头
        s_string(fuzz_part, name=name + "_fuzz", max_len=1024)
        s_static("\x00")  # 常见分隔符

    # 客户端握手阶段
    define_vpn_stage("CLIENT_HELLO", "CLIENT_HELLO\x01", "vpn_client_1.0")
    # 身份认证请求
    s_initialize("AUTH_REQUEST")
    s_static(b"\x02\x00\x00\x00")  # 假设的协议版本标识
    s_group("auth_type", values=[b"\x01", b"\x02", b"\xFF"])  # 认证类型
    s_random("credentials", min_length=16, max_length=256, num_mutations=10,fuzzable=True)

    # 加密隧道数据
    s_initialize("TUNNEL_DATA")
    s_static(b"DATA\x00")
    s_block_start("encrypted_payload")
    s_random("iv", min_length=16, num_mutations=5)  # 模拟初始化向量
    s_random("ciphertext", min_length=64, max_length=1024, num_mutations=15)
    s_block_end()

    # 测试流程设计
    session.connect(s_get("CLIENT_HELLO"))
    session.connect(s_get("CLIENT_HELLO"), s_get("AUTH_REQUEST"))
    session.connect(s_get("AUTH_REQUEST"), s_get("TUNNEL_DATA"))

    session.fuzz()






if __name__ == "__main__":
    fuzzing_main()
