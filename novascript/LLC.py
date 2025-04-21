interface_port=''
target_mac_str = 'b4:05:5d:15:3c:78'
target_mac = target_mac_str.split(':')
source_mac_str = 'd4:f5:27:1b:93:df'
source_mac = source_mac_str.split(':')


def fuzzing_main():
    session =Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="LLC")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination',
            fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source',
            fuzzable=False)
        s_bytes(value=bytes([0x00, 0x32]), size=2, max_len=2, name='Length', fuzzable=False)
    with s_block("Logical-Link Control"):
        s_bytes(value=bytes([0xaa]), size=1, max_len=1, name='DSAP', fuzzable=False)
        s_bytes(value=bytes([0xaa]), size=1, max_len=1, name='SSAP', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Control field', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x80, 0x63]), size=2, max_len=2, name='Organization Code', fuzzable=False)
        s_bytes(value=bytes([0x08, 0x00]), size=2, max_len=2, name='Protocol ID', fuzzable=False)
    with s_block("Data"):
        s_bytes(value=bytes([0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00,
                             0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03,
                             0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01]),
                size=42, max_len=42, name='allData', fuzzable=True)

    session.connect(s_get('LLC'))


if __name__ == "__main__":
    fuzzing_main()
