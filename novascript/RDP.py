
host_ip = ''
host_port = 3389

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()

def fuzzing_define_proto(session):
    s_initialize(name="RDP")
    with s_block("RDP"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='FORMAT',fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved',fuzzable=False)
        s_bytes(value=bytes([0x00, 0x13]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0x0e]), size=1, max_len=1, name='length2',fuzzable=False)
        s_bytes(value=bytes([0xe0]), size=1, max_len=1, name='PDU',fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='dst.reference', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='src.reference', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='class',fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='type',fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='flag',fuzzable=True)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='length3',fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='end', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00, 0x00]), size=4, max_len=4, name='requestedprotocol', fuzzable=True)


    session.connect(s_get("RDP"))

    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
