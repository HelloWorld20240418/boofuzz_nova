
interface_port = ''
src_ip = []
dst_ip = []


def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)),  nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()



def fuzzing_define_proto(session):
    s_initialize(name="IPv6_TCP")
    with s_block("Ethernet II"):
        s_bytes(value=bytes([0x68, 0x91, 0xd0, 0x66, 0x43, 0xa4]), size=6, max_len=6, name='Destination',
                fuzzable=False)
        s_bytes(value=bytes([0x68, 0x91, 0xd0, 0x66, 0xb0, 0x00]), size=6, max_len=6, name='Source', fuzzable=False)
        s_bytes(value=bytes([0x86, 0xdd]), size=2, max_len=2, name='Type', fuzzable=False)
    with s_block("IPv6"):
        s_bytes(value=bytes([0x60]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x18]), size=2, max_len=2, name='Payload Length', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Next Header', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Hop Limit', fuzzable=False)
        s_bytes(value=bytes(
            src_ip), size=16,
                max_len=16, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(
            dst_ip), size=16,
                max_len=16, name='Destination Address', fuzzable=False)
    with s_block("Transmission_Control_Portocol"):
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Source Port', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x50]), size=2, max_len=2, name='Destination Port', fuzzable=False)
        s_bytes(value=bytes([0x77, 0x32,0xf2,0x60]), size=4, max_len=4, name='Sequence_number', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x00]), size=4, max_len=4, name='acknowledgment_number', fuzzable=True)
        s_bytes(value=bytes([0x60, 0x02]), size=2, max_len=2, name='flags', fuzzable=False)
        s_bytes(value=bytes([0xea, 0x60]), size=2, max_len=2, name='window', fuzzable=False)
        s_checksum(block_name='Transmission_Control_Portocol', algorithm='udp', name='Checksum',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='urgent_pointer', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='option_kind', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='option_length', fuzzable=False)
        s_bytes(value=bytes([0x05,0xa0]), size=2, max_len=2, name='option_mms_value', fuzzable=True)

    session.connect(s_get('IPv6_TCP'))


if __name__ == "__main__":
    fuzzing_main()
