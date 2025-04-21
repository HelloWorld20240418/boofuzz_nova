
host_ip = ''
host_port = 1935

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()

def fuzzing_define_proto(session):
    s_initialize(name="RTMP")
    with s_block("RTMP"):
        s_bytes(value=bytes([0x43]), size=1, max_len=1, name='FORMAT',fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00]), size=3, max_len=3, name='timestamp', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x19]), size=3, max_len=3, name='bodysize', fuzzable=True)
        s_bytes(value=bytes([0x14]), size=1, max_len=1, name='type.ID', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='AMF0.type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0c]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0x63,0x72,0x65,0x61,0x74,0x65,0x53,0x74,0x72,0x65,0x61,0x6d]), size=12, max_len=12, name='string', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='AMFO2.type', fuzzable=False)
        s_bytes(value=bytes([0X40,0X00,0x00,0X00,0x00,0X00,0x00,0x00]), size=8, max_len=8, name='NUMBER', fuzzable=True)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='AMFO3.type', fuzzable=True)



    session.connect(s_get("RTMP"))
    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
