host_ip = ''
host_port = 50000


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="DRDA")
    with s_block("DRDA"):

        s_bytes(value=bytes([0x00,0x0a]), size=2, max_len=2, name='TYPE', fuzzable=False)
        s_bytes(value=bytes([0xd0]), size=1, max_len=1, name='magic', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='format', fuzzable=True)
        s_bytes(value=bytes([0x0e, 0x01]), size=2, max_len=2, name='corre1id', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name='length2', fuzzable=True)
        s_bytes(value=bytes([0x20, 0x0e]), size=2, max_len=2, name='codepoint', fuzzable=True)


        session.connect(s_get('DRDA'))


if __name__ == "__main__":
    fuzzing_main()