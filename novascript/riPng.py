
interface_port = ''
src_ip = []
dst_ip = []

def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x86dd)), nova_session_param=nova_session_param )
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="RIPng")
    with s_block("IPv6"):
        s_bytes(value=bytes([0x60]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x20]), size=2, max_len=2, name='Payload Length', fuzzable=False)
        s_bytes(value=bytes([0x11]), size=2, max_len=2, name='Next Header', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Hop Limit', fuzzable=False)
        s_bytes(value=bytes(src_ip), size=16, max_len=16, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=16, max_len=16, name='Destination Address', fuzzable=False)
    with s_block("udp"):
        s_bytes(value=bytes([0xcd,0x3b]), size=2, max_len=2, name='source.port', fuzzable=True)
        s_bytes(value=bytes([0x02,0x09]), size=2, max_len=2, name='dst.port', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x20]), size=2, max_len=2, name='Length', fuzzable=False)
        s_checksum(block_name='udp', algorithm='udp', name='Checksum',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        #s_bytes(value=bytes([0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         #                    ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01]), size=24, max_len=24, name='payload', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='command', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=16, max_len=16, name='IPV6.Prefix', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='route.tag', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Prefix.length', fuzzable=False)
        s_bytes(value=bytes([0x10]), size=1, max_len=1, name='metric', fuzzable=False)

    session.connect(s_get('RIPng'))


if __name__ == "__main__":
    fuzzing_main()
