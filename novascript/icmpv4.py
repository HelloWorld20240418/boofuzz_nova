interface_port = ''
src_ip = []
dst_ip = []

def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x0800)),nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="icmpv4")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x3c]), name='Total_length', fuzzable=False)
        s_bytes(value=bytes([0xc6,0x3e]), name='identification', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), name='flags', fuzzable=False)
        s_bytes(value=bytes([0x80]), name='time_to_live', fuzzable=False)
        s_bytes(value=bytes([0x01]), name='protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes(src_ip),size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("icmp"):
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Code', fuzzable=False)
        s_checksum("icmp", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes([0x02, 0x00]), size=2, max_len=2, name='Identifier(BE)', fuzzable=True)
        s_bytes(value=bytes([0x09,0x00]), size=2, max_len=2, name='Sequence_nuber')
        s_bytes(value=bytes([0x00]), size=32, max_len=32, name='Data')
    session.connect(s_get('icmpv4'))


if __name__ == "__main__":
    fuzzing_main()