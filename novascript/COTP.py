interface_port=''
target_mac_str = '08:00:06:39:11:11'
target_mac = target_mac_str.split(':')
source_mac_str = '08:00:06:39:11:12'
source_mac = source_mac_str.split(':')

def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="cotp")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination',
            fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source',
            fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0e]), size=2, max_len=2, name='Length', fuzzable=False)
    with s_block("Logical_link_Control"):
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='SAP1', fuzzable=False)
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='SAP2', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='command', fuzzable=False)
    with s_block("ISO8473/x.233"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='inactive_subset', fuzzable=False)
    with s_block("ISO8473/x.224"):
        s_bytes(value=bytes([0x09]), size=1, max_len=1, name='length', fuzzable=False)
        s_bytes(value=bytes([0x60]), size=1, max_len=1, name='PDU_TYPE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x07]), size=2, max_len=2, name='Destination_reference', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x34, 0x57]), size=4, max_len=4, name='Your_TPDU_numbe', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Credite')
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00]), size=32, max_len=32, name='padding', fuzzable=True)
    session.connect(s_get('cotp'))


if __name__ == "__main__":
    fuzzing_main()
