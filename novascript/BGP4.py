
interface_port = ''
src_ip = []
dst_ip = []


def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x86dd)),nova_session_param=nova_session_param)
    fuzzing_open_message(session=session)
    fuzzing_KEEPALIVE_Message(session=session)
    session.fuzz()


def fuzzing_open_message(session):
    s_initialize(name="open_message")
    with s_block("IPv6"):
        s_bytes(value=bytes([0x6c]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x4d]), size=2, max_len=2, name='Payload Length', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Next Header', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Hop Limit', fuzzable=False)
        s_bytes(value=bytes(
            src_ip), size=16,
                max_len=16, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(
            dst_ip), size=16,
                max_len=16, name='Destination Address', fuzzable=False)
    with s_block("Transmission_Control_Portocol"):
        s_bytes(value=bytes([0x9d, 0x3f]), size=2, max_len=2, name='Source Port', fuzzable=True)
        s_bytes(value=bytes([0x00, 0xb3]), size=2, max_len=2, name='Destination Port', fuzzable=False)
        s_bytes(value=bytes([0x9c, 0x73, 0x6d, 0x15]), size=4, max_len=4, name='Sequence_number', fuzzable=True)
        s_bytes(value=bytes([0x82, 0xd9, 0x4b, 0xe3]), size=4, max_len=4, name='acknowledgment_number',
                    fuzzable=False)
        s_bytes(value=bytes([0x50, 0x18]), size=2, max_len=2, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x40, 0x00]), size=2, max_len=2, name='window', fuzzable=False)
        s_checksum(block_name='Transmission_Control_Portocol', algorithm='udp', name='Checksum',
                       ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                       length=2, fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='urgent_pointer', fuzzable=False)
    with s_block("BGP"):
        s_bytes(value=bytes([0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff]), name='bgp.marker', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x39]), size=2, max_len=2, name='bgp.length', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='bgp.type', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='bgp.open.version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x64]), size=2, max_len=2, name='bgp.open.myas', fuzzable=False)
        s_bytes(value=bytes([0x00,0xb4]), size=4, max_len=4, name='bgp.open.holdtime', fuzzable=True)
        s_bytes(value=bytes([0x0a, 0x00, 0x00, 0x02]), size=4, max_len=4, name='bgp.open.identifier', fuzzable=True)
        s_bytes(value=bytes([0x1c]), size=1, max_len=1, name='bgp.open.opt.len', fuzzable=False)
        s_bytes(value=bytes([0x02]),name='bgp.open.opt.param.type', fuzzable=False)
        s_bytes(value=bytes([0x06]), name='Parameter Length: 6', fuzzable=False)
        s_bytes(value=bytes([0x01]),  name='bgp.cap.type', fuzzable=False)
        s_bytes(value=bytes([0x04]), name='bgp.cap.length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x02]), name='bgp.cap.mp.afi', fuzzable=False)
        s_bytes(value=bytes([0x00]), name='obgp.cap.reserved', fuzzable=False)
        s_bytes(value=bytes([0x85]), name='bgp.cap.mp.safi', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='bgp.open.opt.param.type_1', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='Parameter Length: 6_1', fuzzable=False)
        s_bytes(value=bytes([0x80]), name='bgp.cap.type_1', fuzzable=False)
        s_bytes(value=bytes([0x00]), name='bgp.cap.length_1', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='bgp.open.opt.param.type_2', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='Parameter Length: 6_2', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='bgp.cap.type_2', fuzzable=False)
        s_bytes(value=bytes([0x00]), name='bgp.cap.length_2', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='bgp.open.opt.param.type_3', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='Parameter Length: 6_3', fuzzable=False)
        s_bytes(value=bytes([0x46]), name='bgp.cap.type_3', fuzzable=False)
        s_bytes(value=bytes([0x00]), name='bgp.cap.length_3', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='bgp.open.opt.param.type_4', fuzzable=False)
        s_bytes(value=bytes([0x06]), name='Parameter Length: 6_4', fuzzable=False)
        s_bytes(value=bytes([0x41]), name='bgp.cap.type_4', fuzzable=False)
        s_bytes(value=bytes([0x04]), name='bgp.cap.length_4', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x64]), name='bgp.cap.mp.afi_4', fuzzable=False)


    session.connect(s_get('open_message'))

def fuzzing_KEEPALIVE_Message(session):
    s_initialize(name="KEEPALIVE_Message")
    with s_block("IPv6"):
        s_bytes(value=bytes([0x6c]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x4d]), size=2, max_len=2, name='Payload Length', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Next Header', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Hop Limit', fuzzable=False)
        s_bytes(value=bytes(
            src_ip), size=16,
                max_len=16, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(
            dst_ip), size=16,
                max_len=16, name='Destination Address', fuzzable=False)
    with s_block("Transmission_Control_Portocol"):
        s_bytes(value=bytes([0x9d, 0x3f]), size=2, max_len=2, name='Source Port', fuzzable=True)
        s_bytes(value=bytes([0x00, 0xb3]), size=2, max_len=2, name='Destination Port', fuzzable=False)
        s_bytes(value=bytes([0x9c, 0x73, 0x6d, 0x15]), size=4, max_len=4, name='Sequence_number', fuzzable=False)
        s_bytes(value=bytes([0x82, 0xd9, 0x4b, 0xe3]), size=4, max_len=4, name='acknowledgment_number',
                    fuzzable=False)
        s_bytes(value=bytes([0x50, 0x18]), size=2, max_len=2, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x40, 0x00]), size=2, max_len=2, name='window', fuzzable=False)
        s_checksum(block_name='Transmission_Control_Portocol', algorithm='udp', name='Checksum',
                       ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                       length=2, fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='urgent_pointer', fuzzable=False)
    with s_block("BGP"):
        s_bytes(value=bytes([0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff]), name='bgp.marker', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x13]), size=2, max_len=2, name='bgp.length', fuzzable=True)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='bgp.type', fuzzable=True)
    session.connect(s_get('KEEPALIVE_Message'))
if __name__ == "__main__":
    fuzzing_main()
