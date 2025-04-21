

host_ip = ''
host_port = 2001


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param )

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="DJIUAV")
    with s_block("DJIUAV"):
        s_bytes(value=bytes([0x55,0xbb]), size=2, max_len=2, name='protocol_magic', fuzzable=True)
        s_bytes(value=bytes([0x09]), size=1, max_len=1, name='PDU_length', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Sequence.no', fuzzable=True)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='PDU_type', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='c_UNKNOWN', fuzzable=True)
        s_bytes(value=bytes([0xea]), size=1, max_len=1, name='CHECKSUM', fuzzable=True)




        session.connect(s_get('DJIUAV'))


if __name__ == "__main__":
    fuzzing_main()