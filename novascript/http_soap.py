
host_ip = ''
host_port = 80

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", [ "POST","GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
                            "GET1", "HEAD2", "POST8", "PUT4", "DELETE5", "CONNECT3", "OPTIONS1", "TRACE1"])
        s_delim(" ", name="space-1",fuzzable=False)
        s_string("/Mutillidae/webservices/soap/ws-user-account.php?wsdl", name="Request-URI",fuzzable=True)
        s_delim(" ", name="space-2",fuzzable=False)
        s_string("HTTP/1.1", name="HTTP-Version",fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF")
        s_string("Host:", name="Host-Line",fuzzable=True)
        s_delim(" ", name="space-3",fuzzable=False)
        s_string("example.com", name="Host-Line-Value",fuzzable=True)
        s_static("\r\n", name="Host-Line-CRLF")
        s_static("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nReferer: http://xxxx/Mutillidae/webservices/soap/ws-user-account.php\r\nCookie: PHPSESSID=ek29ufjof62d3fvi8cikgqgb3e; showhints=1\r\nUpgrade-Insecure-Requests: 1\r\nPriority: u=0, i\r\n")
        s_string("fuzz", name="Request-CRLF")
    session.connect(s_get("Request"))


if __name__ == "__main__":
    fuzzing_main()
