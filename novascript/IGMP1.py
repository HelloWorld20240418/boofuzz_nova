from boofuzz import *
interface_port = ''
src_ip = []
dst_ip = []

def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x0800)),nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="IGMP")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x2e]), size=2, max_len=2, name='Total_length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='identification', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='time_to_live', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("IGMP v1"):
        s_bytes(value=bytes([0x12]), size=1, max_len=1, name='Type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved', fuzzable=False)
        s_checksum("IGMP v1", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes([0xe1, 0x01,0x01,0x0a]), size=4, max_len=4, name='igmp.maddr', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=18, max_len=18, name='DATA', fuzzable=True)

    session.connect(s_get('IGMP'))


if __name__ == "__main__":
    fuzzing_main()