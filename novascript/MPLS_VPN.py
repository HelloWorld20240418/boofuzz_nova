
interface_port = ''
src_ip = []
dst_ip = []

# nova_session_param=nova_session_param
def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="MPLS_VPN")
    with s_block("Ethernet II"):
        s_bytes(value=bytes([0x00, 0xE0, 0xf4, 0x08, 0x2f, 0x77]), size=6, max_len=6, name='Destination',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0xa0, 0xf4, 0x08, 0x2f, 0x77]), size=6, max_len=6, name='Source', fuzzable=False)
        s_bytes(value=bytes([0x88, 0x47]), size=2, max_len=2, name='Type', fuzzable=False)
    with s_block("mpls"):
        s_bytes(value=bytes([0x00, 0x40,0x20,0xfd]), size=4, max_len=4, name='mpls.label', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x40,0x71,0xfe]), size=4, max_len=4, name='mpls.tt', fuzzable=False)
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x54]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x3c]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='Time to Live', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("ICMP"):
        with s_block("icmp"):
            s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Type', fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Code', fuzzable=False)
            s_checksum("icmp", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
            s_bytes(value=bytes([0xd1, 0xab]), size=2, max_len=2, name='Identifier(BE)', fuzzable=True)
            s_bytes(value=bytes([0x02, 0x00]), size=2, max_len=2, name='Sequence_nuber')
            s_bytes(value=bytes([0x86,0xc1,0x94,0x00,0xcf,0x1d,0x1e,0xb6,0x50,0x49,0x4e,0x50,0x3e,0x6d,0x28,0x4b,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27]), size=56, max_len=56, name='Data')
    session.connect(s_get('MPLS_VPN'))


if __name__ == "__main__":
    fuzzing_main()
