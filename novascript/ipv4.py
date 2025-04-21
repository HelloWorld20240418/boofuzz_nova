
interface_port = ''
src_ip = []
dst_ip = []


def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x0800)),  nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="IPv4")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x30]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0x80, 0x4c]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x40, 0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Time to Live', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("Data"):
        s_bytes(value=bytes
        ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=30, max_len=30, name='Data', fuzzable=True)
    session.connect(s_get('IPv4'))


if __name__ == "__main__":
    fuzzing_main()
