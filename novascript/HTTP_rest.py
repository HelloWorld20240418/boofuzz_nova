host_ip = ''
host_port = 80

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", [  "POST","GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
                            "GET1", "HEAD2", "POST8", "PUT4", "DELETE5", "CONNECT3", "OPTIONS1", "TRACE1"])
        s_delim(" ", name="space-1",fuzzable=False)
        s_string("/v1/getenv", name="Request-URI",fuzzable=False)
        s_delim(" ", name="space-2",fuzzable=False)
        s_string("HTTP/1.1", name="HTTP-Version",fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF")
        s_string("Host:", name="Host-Line",fuzzable=False)
        s_delim(" ", name="space-3",fuzzable=False)
        s_string("example.com", name="Host-Line-Value",fuzzable=True)
        s_static("\r\n", name="Host-Line-CRLF")
        s_static("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8\r\nConnection: keep-alive Upgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36\r\n")
        s_string("\n", name="Request-CRLF")
    session.connect(s_get("Request"))


if __name__ == "__main__":
    fuzzing_main()
