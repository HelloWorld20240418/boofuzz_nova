

host_ip = ''
host_port = 9042

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="CQL")
    with s_block("CQL"):
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='stream_identifier', fuzzable=False)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='opcode', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='length', fuzzable=True)

        session.connect(s_get('CQL'))


if __name__ == "__main__":
    fuzzing_main()