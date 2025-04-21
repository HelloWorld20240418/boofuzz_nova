from boofuzz import *


host_ip = '192.168.16.254'
host_port = 80

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),
                      fuzz_db_keep_only_n_pass_cases=10,
                      #index_start=1000,
                      #index_end=1200,
                      #keep_web_open=False
                      )

    fuzzing_http_request(session=session)

    session.fuzz(max_depth=1)


def fuzzing_http_request(session):
    s_initialize(name="Request")
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

    session.connect(s_get("Request"))


if __name__ == "__main__":
    fuzzing_main()
