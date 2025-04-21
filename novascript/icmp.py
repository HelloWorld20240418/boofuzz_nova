
interface_port = ''
src_ip = []
dst_ip = []

def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x86dd)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="ICMPv6")
    with s_block("IPv6"):
        s_bytes(value=bytes([0x60]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x1a]), size=2, max_len=2, name='Payload Length', fuzzable=False)
        s_bytes(value=bytes([0x3a]), size=2, max_len=2, name='Next Header', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='Hop Limit', fuzzable=False)
        s_bytes(value=bytes(src_ip), size=16, max_len=16, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=16, max_len=16, name='Destination Address', fuzzable=False)
    with s_block("Internet Control Message Protocol v6"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Code', fuzzable=False)
        s_checksum(block_name='Internet Control Message Protocol v6', algorithm='udp', name='Checksum',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Identifier', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Sequence', fuzzable=True)

        s_bytes(value=bytes(
            [0x01, 0x01, 0x68, 0x91, 0xd0, 0x69, 0x38, 0x94, 0x01, 0x01, 0x68, 0x91, 0xd0, 0x69, 0x38, 0x94, 0x00, 0x00]), size=18, max_len=18, name='Data', fuzzable=True)
    session.connect(s_get('ICMPv6'))


if __name__ == "__main__":
    fuzzing_main()
