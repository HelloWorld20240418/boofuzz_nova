
host_ip = ''
host_port = 5050

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="ETHERSBUS")
    with s_block("gvsp"):
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='status', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0d]), size=2, max_len=2, name='block_id', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='format', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x01]), size=3, max_len=3, name='packetid', fuzzable=True)
        s_bytes(value=bytes([0x00,0x0a,0x20,0x53,0x18]), size=5, max_len=5, name='end', fuzzable=True)
    session.connect(s_get('ETHERSBUS'))


if __name__ == "__main__":
    fuzzing_main()


