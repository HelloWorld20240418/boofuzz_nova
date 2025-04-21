
host_ip = ''
host_port = 31601


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_RTCP(session=session)
    session.fuzz()


#流的生产者需要发送 SR 报文，SR 报文包含该流的发送包数，发送字节数，流的接收者可以根据发送者报文结合自己的接收情况计算丢包率等信息。
def fuzzing_RTCP(session):
    s_initialize(name="SR")
    with s_block("Real-time Transport Control Protocol"):
        s_byte(0x81, name="Version", fuzzable=False)
        s_byte(0xc8, name="Packet type", fuzzable=False)
        s_word(0x000c, name="Length", fuzzable=False)
        s_dword(0x5d931534, name="Sender SSRC", fuzzable=False)
        s_dword(0xdd3ac170, name="Timestamp, MSW", fuzzable=False)
        s_dword(0x4d614df8, name="Timestamp, LSW", fuzzable=False)
        s_dword(0x00007d00, name="RTP timestamp", fuzzable=False)
        s_dword(0x000000c8, name="Sender's packet count", fuzzable=False)
        s_dword(0x00007d00, name="Sender's octet count", fuzzable=False)
        with s_block("Source1"):
            s_dword(0x00000000, name="Identifier", fuzzable=False)
            with s_block("SSRC contents"):
                s_byte(0x00, name="Fraction lost: 0 / 256", fuzzable=False)
                s_bytes(value=b"\x00\x00\x01", name="Cumulative number of packets lost: 1")
            s_dword(0x00000000, name="Extended highest sequence number received: 0", fuzzable=False)
            s_dword(0x00000000, name="Interarrival jitter: 0", fuzzable=False)
            s_dword(0x00000000, name="Last SR timestamp: 0 (0x00000000)", fuzzable=False)
            s_dword(0x00000000, name="Delay since last SR timestamp: 0 (0 milliseconds)", fuzzable=False)
        with s_block("Real-time Transport Control Protocol Source description"):
            s_byte(0x81, name="Version", fuzzable=False)
            s_byte(0xca, name="Packet type", fuzzable=False)
            s_word(0x000e, name="Length", fuzzable=False)
            with s_block("Chunk 1, SSRC/CSRC 0x5D931534"):
                s_dword(0x5d931534, name="Identifier", fuzzable=False)
                with s_block("SDES items"):
                    s_static("\x01", name="Type CNAME")
                    s_byte(0x08, name="Length", fuzzable=False)
                    s_string("5d931534", name="Text", fuzzable=True)
                    s_static("\x07", name="Type NOTE")
                    s_byte(0x25, name="Length2", fuzzable=False)
                    s_string("FreeSWITCH.org -- Come to ClueCon.com", name="Text2", size=37, max_len=37, fuzzable=True)
                    s_byte(0x00, name="Type END", fuzzable=False)


    session.connect(s_get('SR'))


if __name__ == "__main__":
    fuzzing_main()
