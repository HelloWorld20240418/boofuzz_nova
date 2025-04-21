
host_ip = ''
host_port = 80

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_http_request(session=session)

    session.fuzz()


def fuzzing_http_request(session):
    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"])
        s_delim(" ", name="space-1", fuzzable=False)
        s_string("/index.html", name="Request-URI")
        s_delim(" ", name="space-2", fuzzable=False)
        s_string("HTTP/1.1", name="HTTP-Version", fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF")
        s_string("Host:", name="Host-Line", fuzzable=False)
        s_delim(" ", name="space-3", fuzzable=False)
        s_string("example.com", name="Host-Line-Value", fuzzable=False)
        s_static("\r\n", name="Host-Line-CRLF")
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get("Request"))


if __name__ == "__main__":
    fuzzing_main()
