host_ip = ''
host_port = 1433

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_TDS(session=session)

    session.fuzz()


def fuzzing_TDS(session):
    s_initialize(name="TDS")
    with s_block("TDS"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='TPYE',fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='STATUS',fuzzable=False)
        s_bytes(value=bytes([0x00,0x2e]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='channel', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='packet_number',fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='window',fuzzable=False)
        s_bytes(value=bytes([0x73,0x00,0x65,0x00,0x74,0x00,0x20,0x00,0x74,0x00,0x65,0x00,0x78,0x00,0x74,0x00,0x73,0x00,0x69,0x00,0x7a,0x00,0x65,0x00,0x20,0x00,0x36,0x00,0x34,0x00,0x35,0x00,0x31,0x00,0x32,0x00,0x20,0x00]), size=38, max_len=38, name='TDS',fuzzable=True)

        s_bytes(value=bytes([0x52,0x54,0x50,0x53]), size=4, max_len=4, name='MAGIC', fuzzable=True)
        s_bytes(value=bytes([0x02,0x01]), size=2, max_len=2, name='protocol.version', fuzzable=False)
        s_bytes(value=bytes([0x01,0x01]), size=2, max_len=2, name='rtps.vendorId', fuzzable=False)
        s_bytes(value=bytes([0x4e,0x44,0x44,0x53,0x50,0x49,0x4e,0x47]), size=8, max_len=8, name='text', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='pad', fuzzable=False)


    session.connect(s_get('TDS'))

if __name__ == "__main__":
    fuzzing_main()