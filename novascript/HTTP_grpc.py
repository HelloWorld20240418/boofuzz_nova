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
        s_string("/greet.Greeter/SayHello", name="Request-URI",fuzzable=False)
        s_delim(" ", name="space-2",fuzzable=False)
        s_string("HTTP/1.1", name="HTTP-Version",fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF")
        s_string("Host:", name="Host-Line",fuzzable=False)
        s_delim(" ", name="space-3",fuzzable=False)
        s_string("localhost:57226", name="Host-Line-Value",fuzzable=True)
        s_static("\r\n", name="Host-Line-CRLF")
        s_static("User-Agent: grpc-dotnet/2.41.0-pre1 (.NET 6.0.2; CLR 6.0.2; net6.0; windows; x64)\nTE: trailers\ngrpc-accept-encoding: identity,gzip\nAccept: application/grpc-web-text\nTransfer-Encoding: chunked\nContent-Type: application/grpc-web-text\r\n")
        s_static("\r\n", name="post")
        s_string("14\nAAAAAAoKCDg4ODg4ODg4\n0\r\n", name="body")


    session.connect(s_get("Request"))


if __name__ == "__main__":
    fuzzing_main()
