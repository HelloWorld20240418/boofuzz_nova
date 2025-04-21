

host_ip = ''
host_port = 13400

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="DoIP")
    with s_block("DoIP"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='inverse_version', fuzzable=False)
        s_bytes(value=bytes([0x00,0x05]), size=2, max_len=2, name='TYPE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x08]), size=4, max_len=4, name='length', fuzzable=False)
        s_bytes(value=bytes([0x0e, 0x80]), size=2, max_len=2, name='src.add', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='activation_type', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x00]), size=4, max_len=4, name='reserved', fuzzable=True)


        session.connect(s_get('DoIP'))


if __name__ == "__main__":
    fuzzing_main()