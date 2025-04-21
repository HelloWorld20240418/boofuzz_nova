host_ip = ''
host_port = 8080

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_http_request(session=session)
    session.fuzz()
def fuzzing_http_request(session):
    # 定义 WebSocket 握手请求（HTTP Upgrade）
    s_initialize(name="websocket_handshake")
    s_static("GET /websocket HTTP/1.1\r\n")
    s_static("Host: localhost:8080\r\n")
    s_static("Upgrade: websocket\r\n")
    s_static("Connection: Upgrade\r\n")
    s_static("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")  # 固定或动态生成
    s_static("Sec-WebSocket-Version: 13\r\n\r\n")

    # 定义 WebSocket 数据帧（基于 RFC6455 帧格式）
    s_initialize(name="websocket_frame")
    with s_block("frame_header"):
        # FIN + RSV + Opcode (4 bits)
        s_byte(0x81, name="fin_and_opcode", fuzzable=True)  # 默认文本帧（0x81），模糊操作码
        # Mask + Payload Length (7 bits)
        s_byte(0x80, name="mask_and_length", fuzzable=True)  # 掩码位 + 长度
        # Extended Payload Length (如果长度 >=126)
        s_size("payload_data", length=2, name="extended_length", fuzzable=True)  # 模糊扩展长度
        # Masking Key
        s_random("mask_key", min_length=4, max_length=4, num_mutations=10)  # 随机掩码密钥
    # 负载数据（需应用掩码）
    with s_block("payload_data"):
        s_string("Hello, Server!", name="payload", fuzzable=True)  # 模糊负载内容

    # 定义测试顺序：先握手，后发送数据帧
    session.connect(s_get("websocket_handshake"))
    session.connect(s_get("websocket_handshake"), s_get("websocket_frame"))

    # 启动模糊测试
    session.fuzz()

if __name__ == "__main__":
    fuzzing_main()
