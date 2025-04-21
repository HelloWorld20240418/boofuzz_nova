

host_ip = ''
host_port = 48898


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param )

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="beckoff")
    with s_block("beckoff"):
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x28, 0x00, 0x00]), size=6, max_len=6, name='ams.header',fuzzable=False)
        s_bytes(value=bytes([0x05,0x0d,0x75,0x60,0x01,0x01]), size=6, max_len=6, name='ams.targetnetid', fuzzable=False)
        s_bytes(value=bytes([0x10,0x27]), size=2, max_len=2, name='ams.targetport', fuzzable=True)
        s_bytes(value=bytes([0xc0,0xa8,0x01,0x63,0x01,0x01]), size=6, max_len=6, name='ams.sendernetid', fuzzable=False)
        s_bytes(value=bytes([0x78,0x82]), size=2, max_len=2, name='ams.senderport', fuzzable=False)
        s_bytes(value=bytes([0x04,0x00]), size=2, max_len=2, name='ams.cmdid', fuzzable=True)
        s_bytes(value=bytes([0x06,0x00]), size=2, max_len=2, name='stateflags', fuzzable=True)
        s_bytes(value=bytes([0x08,0x00,0x00,0x00]), size=4, max_len=4, name='cbdata', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='errorcode', fuzzable=True)
        s_bytes(value=bytes([0x03,0x00,0x00,0x00]), size=4, max_len=4, name='invokeid', fuzzable=True)
        session.connect(s_get('beckoff'))


if __name__ == "__main__":
    fuzzing_main()