host_ip = ''
host_port = 554

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_http_request(session=session)
    session.fuzz()


def fuzzing_http_request(session):
    s_initialize(name="Request")
    with s_block("Request"):
        s_group("Method", ["DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN", "RECORD", "OPTIONS", "ANNOUNCE","NEW","UPDATE","RESTART"])
        s_delim(" ", name="space-1", fuzzable=False)
        s_string("rtsp://EMAP1.planetwideradio.com/tfm RTSP/1.0", name="Request-URI", fuzzable=False)
        s_static("\r\n", name="Request-Line-CRLF2")
        s_delim("User-Agent: ", name="space-3", fuzzable=False)
        s_string("WMPlayer/10.0.0.380 guid/7405E143-26AC-4B37-9802-A35EE8C6CFA7", name="User-Agent", fuzzable=True)
        s_static("\r\n", name="Host-Line-CRLF3")
        s_delim("Accept: ", name="space-2", fuzzable=False)
        s_string("application/sdp", name="Accept: ", fuzzable=True)
        s_static("\r\n", name="Host-Line-CRLF2")
        s_delim("Accept-Charset: ", name="space_Accept-Charset", fuzzable=False)
        s_string("UTF-8, *;q=0.1", name="Accept-Charset", fuzzable=True)
        s_static("\r\n", name="Accept-Charset_Host-Line-CRLF2")
        s_delim("X-Accept-Authentication: ", name="X-Accept-Authentication: -Charset", fuzzable=False)
        s_string("Negotiate, NTLM, Digest, Basic", name="X-Accept-Authentication: ", fuzzable=True)
        s_static("\r\n", name="X-Accept-Authentication: -Line-CRLF2")
        s_delim("Accept-Language:", name="Accept-Language:_space-4", fuzzable=False)
        s_string("en-GB, *;q=0.1", name="Accept-Language", fuzzable=False)
        s_static("\r\n", name="Accept-Language-CRLF4")
        s_delim("CSeq: ", name="CSeq:-5", fuzzable=False)
        s_string("1", name="CSeq", fuzzable=False)
        s_static("\r\n", name="CSeq: -Line-CRLF5")

        s_delim("Supported: ", name="Supported: -6", fuzzable=False)
        s_string("com.microsoft.wm.srvppair, com.microsoft.wm.sswitch, com.microsoft.wm.eosmsg, com.microsoft.wm.predstrm, com.microsoft.wm.startupprofile", name="Supported: ", fuzzable=True)
        s_static("\r\n", name="Supported:_CRLF6")


    session.connect(s_get("Request"))


if __name__ == "__main__":
    fuzzing_main()