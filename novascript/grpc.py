host_ip = ''
host_port = 8000

def main():

    # 初始化会话
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    # 定义HTTP/2基础帧结构
    def define_http2_frame(name, type_value):
        s_initialize(name)
        with s_block("FrameHeader"):
            # 长度字段（24位），实际使用3字节表示
            s_bit_field(0x00, width=24, name="Length", fuzzable=True)
            # 类型字段（8位）
            s_byte(type_value, name="Type", fuzzable=False)  # 可改为True以模糊类型
            # 标志字段（8位）
            s_byte(0x00, name="Flags", fuzzable=True)
            # 流标识符（31位），最高位保留
            s_bit_field(0x00000000, width=31, name="StreamID", fuzzable=True)
        # 负载数据（长度由Length字段动态决定）
        s_size("Payload", length=3, fuzzable=True, math=lambda x: x)  # 关联Length字段
        with s_block("Payload"):
            s_random("Data", min_length=1, max_length=1024, num_mutations=100)

    # 定义HTTP/2连接前导魔术字节
    s_initialize("HTTP2_Preface")
    s_static(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")  # HTTP/2必须的前导

    # 定义HEADERS帧（类型0x01）
    define_http2_frame("HEADERS_Frame", type_value=0x01)

    # 定义DATA帧（类型0x00）
    define_http2_frame("DATA_Frame", type_value=0x00)

    # 定义测试顺序
    session.connect(s_get("HTTP2_Preface"))
    session.connect(s_get("HTTP2_Preface"), s_get("HEADERS_Frame"))
    session.connect(s_get("HEADERS_Frame"), s_get("DATA_Frame"))

    # 开始模糊测试
    session.fuzz()

if __name__ == "__main__":
    main()