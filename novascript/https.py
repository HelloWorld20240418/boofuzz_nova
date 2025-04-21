
host_ip = ''
host_port = 443

def fuzzing_main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    connection = SSLSocketConnection(host_ip, host_port, sslcontext=context)
    session = Session(target=Target(connection), nova_session_param=nova_session_param)

    s_initialize(name="HTTPS")
    with s_block("Request-Line"):
        s_group("Method", ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"])
        s_delim(" ", name="space-1", fuzzable=False)
        s_string("/index.html", name="Request-URI", fuzzable=True)
        s_delim(" ", name="space-2", fuzzable=False)
        s_string("HTTP/1.1", name="HTTP-Version", fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF")
        s_string("Host:", name="Host-Line", fuzzable=False)
        s_delim(" ", name="space-3", fuzzable=False)
        s_string("example.com", name="Host-Line-Value", fuzzable=False)
        s_static("\r\n", name="Host-Line-CRLF")
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get('HTTPS'))
    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
