import ssl
from boofuzz import *

host_ip = '192.168.16.254'
host_port = 443

def main():

    context = ssl.create_default_context()  #创建默认 SSL 上下文（自动协商 TLS 版本）
    context.check_hostname = False  # 禁用主机名验证
    context.verify_mode = ssl.CERT_NONE  # 禁用证书验证（测试用）

    session = Session(target=Target(connection=SSLSocketConnection(host_ip, host_port,sslcontext=context)),
                      ignore_connection_ssl_errors=True,
                      )

    define_doh_proto(session)
    session.fuzz()


def define_doh_proto(session):
    s_initialize(name="DoH_Request")
    s_static("POST /dns-query HTTP/1.1\r\n")
    s_static("Host: ")
    s_static("www.baidu.com", name="host_value")
    s_static("\r\n")
    s_static("Content-Type: application/dns-message\r\n")
    s_static("Accept: application/dns-message\r\n")

    # 动态Content-Length
    s_size(block_name="dns_body", length=4, output_format="ascii", name="Content_Length", fuzzable=False)
    s_static("\r\n\r\n")

    with s_block("dns_body"):
        s_bytes(value=b"\x00\x00", name="dns_id", fuzzable=True)
        s_static(b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")  # DNS Flags + 计数器 (10字节),DNS头部压缩
        s_string("www.baidu.com", name="dns_query", fuzzable=True)
        s_static(b"\x00\x00\x01\x00\x01") ## 标准DNS查询尾部,QTYPE=A(0x0001), QCLASS=IN(0x0001)

    session.connect(s_get("DoH_Request"))

if __name__ == "__main__":
    main()
