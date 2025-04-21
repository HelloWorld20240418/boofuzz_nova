
host_ip = ''
host_port = 2152


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="user")
    with s_block("GPRS"):
        s_bytes(value=bytes([0x30]), size=1, max_len=1, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x5b]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x1e,0x84,0x80]), size=4, max_len=4, name='TEID', fuzzable=True)
        with s_block("IPv4"):
            s_bytes(value=bytes([0x45]), size=1, max_len=1, name='Version', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x5b]), size=3, max_len=3, name='Traffic Class', fuzzable=True)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Payload Length', fuzzable=False)
            s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='falgs', fuzzable=False)
            s_bytes(value=bytes([0x40]), size=1, max_len=1, name='timetolive', fuzzable=False)
            s_bytes(value=bytes([0x11]), size=1, max_len=1, name='protocol', fuzzable=False)
            s_bytes(value=bytes([0x74,0x8c]), size=2, max_len=2, name='checksum', fuzzable=False)
            s_bytes(value=bytes([0x01, 0x01,0x01, 0x01]), size=4,max_len=4, name='Source Address', fuzzable=False)
            s_bytes(value=bytes([0x02, 0x02,0x02, 0x02]), size=4,max_len=4, name='Destination Address', fuzzable=False)
            s_bytes(value=bytes([0x07, 0xd2]), size=2, max_len=2, name='src.port', fuzzable=True)
            s_bytes(value=bytes([0x07, 0xd3]), size=2, max_len=2, name='dst.port', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x47]), size=2, max_len=2, name='length', fuzzable=False)
            s_bytes(value=bytes([0x26,0x23]), size=2, max_len=2, name='checksum2', fuzzable=False)
            s_string("6162636465666768696a716c6d6e6f707172737475767778797a30313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a", name="data", fuzzable=True)


        session.connect(s_get('user'))






if __name__ == "__main__":
    fuzzing_main()