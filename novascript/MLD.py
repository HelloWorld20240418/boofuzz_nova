
interface_port = ''
src_ip = []
dst_ip = []

def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x86dd)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="MLD")
    with s_block("IPv6"):
        s_bytes(value=bytes([0x60]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x1a]), size=2, max_len=2, name='Payload Length', fuzzable=False)
        s_bytes(value=bytes([0x3a]), size=2, max_len=2, name='Next Header', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='Hop Limit', fuzzable=False)
        s_bytes(value=bytes(src_ip), size=16, max_len=16, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=16, max_len=16, name='Destination Address', fuzzable=False)
    with s_block("Internet Control Message Protocol v6"):
        s_bytes(value=bytes([0x82]), size=1, max_len=1, name='Type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Code', fuzzable=True)
        s_checksum(block_name='Internet Control Message Protocol v6', algorithm='udp', name='Checksum',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        s_bytes(value=bytes([0x27, 0x10]), size=2, max_len=2, name='Identifier', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Sequence', fuzzable=False)
        s_bytes(value=bytes(
            [0x00,0x00, 0x00, 0x00,0x00,0x00, 0x00, 0x00,0x00,0x00, 0x00, 0x00,0x00,0x00, 0x00, 0x00]), size=16, max_len=16, name='address', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='flags', fuzzable=True)
        s_bytes(value=bytes([0x7d]), size=1, max_len=1, name='qqic', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='number', fuzzable=True)
    session.connect(s_get('MLD'))


if __name__ == "__main__":
    fuzzing_main()
