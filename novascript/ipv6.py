
interface_port = ''
src_ip = []
dst_ip = []


def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x86dd)),  nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()



def fuzzing_define_proto(session):
    s_initialize(name="IPv6_udp")
    with s_block("IPv6"):
        s_bytes(value=bytes([0x60]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0d]), size=2, max_len=2, name='Payload Length', fuzzable=False)
        s_bytes(value=bytes([0x11]), size=2, max_len=2, name='Next Header', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Hop Limit', fuzzable=True)
        s_bytes(value=bytes(src_ip), size=16, max_len=16, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=16, max_len=16, name='Destination Address', fuzzable=False)
    with s_block("checksum"):
        s_bytes(value=bytes([0x7f, 0x80]), size=2, max_len=2, name='Source Port', fuzzable=True)
        s_bytes(value=bytes([0x7f, 0x01]), size=2, max_len=2, name='Destination Port', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0d]), size=2, max_len=2, name='Length', fuzzable=False)
        s_checksum("checksum", algorithm='udp', name='Checksum', endian='>', length=2,
                   ipv4_src_block_name='Source Address', ipv4_dst_block_name='Destination Address',
                   fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name='Data', fuzzable=True)

    session.connect(s_get('IPv6_udp'))


if __name__ == "__main__":
    fuzzing_main()
