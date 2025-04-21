
host_ip = ''
host_port = 443


def fuzzing_main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    connection = SSLSocketConnection(host_ip, host_port, sslcontext=context)
    session = Session(target=Target(connection),nova_session_param=nova_session_param)

    # 定义协议字段
    s_initialize(name="doh_request")

    # HTTP请求行
    s_group("method", ["POST", "GET"])
    with s_block("request_line"):
        s_static(" ")
        if s_block_start("method_group", group="method"):
            s_static("/dns-query HTTP/1.1\r\n")  # DoH标准端点
        s_block_end()

    # HTTP头部
    s_static("Host: dns.google\r\n")
    s_static("Accept: application/dns-message\r\n")
    s_static("Content-Type: application/dns-message\r\n")

    # 动态Content-Length（基于实际DNS消息长度）
    with s_block("content_length"):
        s_static("Content-Length: ")
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="ascii", fuzzable=True)
       # s_size("dns_body", output_format="ascii", signed=False)
        s_static("\r\n")

    s_static("\r\n")  # 结束头部

    # 定义模糊字段
    session.connect(s_get("doh_request"))

    # 开始模糊测试
    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
