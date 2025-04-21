interface_port = ''
src_ip = []
dst_ip = []

def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x0800)),nova_session_param=nova_session_param )
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="IPv4")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x28]), size=2, max_len=2, name='Total_length', fuzzable=False)
        s_bytes(value=bytes([0x15,0x06]), size=2, max_len=2, name='identification', fuzzable=False)
        s_bytes(value=bytes([0x40,0x00]), size=2, max_len=2, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='time_to_live', fuzzable=False)
        s_bytes(value=bytes([0x21]), size=1, max_len=1, name='protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=14, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("DCCP"):
        s_bytes(value=bytes([0x80, 0x004]), size=2, max_len=2, name='source.port', fuzzable=False)
        s_bytes(value=bytes([0x13, 0x89]), size=2, max_len=2, name='dst.port', fuzzable=False)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='data.offset', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='CCVal', fuzzable=False)
        s_checksum("DCCP", algorithm='udp', name='Checksum', endian='>', length=2,ipv4_src_block_name='Source Address', ipv4_dst_block_name='Destination Address',fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='tpye', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='dccp.x ', fuzzable=False)
        s_bytes(value=bytes([0x00,0x04,0x29,0x01,0x6d,0xdc]), size=6, max_len=6, name='Sequence_nuber', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='service.code', fuzzable=True)

    session.connect(s_get('IPv4'))


if __name__ == "__main__":
    fuzzing_main()






