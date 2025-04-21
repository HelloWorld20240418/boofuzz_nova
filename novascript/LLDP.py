
interface_port=''
target_mac_str = '01:80:c2:00:00:0e'
target_mac = target_mac_str.split(':')
source_mac_str = 'd4:f5:27:3d:37:58'
source_mac = source_mac_str.split(':')

def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="LLDP")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination',
            fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source',
            fuzzable=False)
        s_bytes(value=bytes([0x88, 0xcc]), size=2, max_len=2, name='Type', fuzzable=False)
    with s_block("Link Layer Discovery Protocol"):
        with s_block("Chassis Subtype"):
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='TLV Type 0', fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name='TLV Length 0', fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Chassis Id Subtype', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x1e, 0xcd, 0x1a, 0x4b, 0xd8]), size=6, max_len=6, name='Chassis Id',
                    fuzzable=False)
        with s_block("Port Subtype"):
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name='TLV Type 1', fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name='TLV Length 1', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Port Id Subtype', fuzzable=False)
            s_bytes(value=bytes([0x50, 0x6f, 0x72, 0x74, 0x5f, 0x34, 0x2f, 0x31]), size=8, max_len=8, name='Port Id',
                    fuzzable=False)
        with s_block("Time To Live"):
            s_bytes(value=bytes([0x06]), size=1, max_len=1, name='TLV Type 2', fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='TLV Length 2', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x14]), size=2, max_len=2, name='Seconds')
        with s_block("Port Description"):
            s_bytes(value=bytes([0x08]), size=1, max_len=1, name='TLV Type 3', fuzzable=False)
            s_bytes(value=bytes([0x08]), size=1, max_len=1, name='TLV Length 3', fuzzable=False)
            s_bytes(value=bytes([0x50, 0x6f, 0x72, 0x74, 0x5f, 0x34, 0x2f, 0x31]), size=8, max_len=8,
                    name='Port Description', fuzzable=True)
        with s_block("System Name"):
            s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='TLV Type 4', fuzzable=False)
            s_bytes(value=bytes([0x10]), size=1, max_len=1, name='TLV Length 4', fuzzable=False)
            s_bytes(value=bytes([0x53, 0x49, 0x43, 0x4f, 0x4d, 0x33, 0x30, 0x32, 0x38, 0x47, 0x50, 0x54, 0x2d, 0x4c,
                                 0x32, 0x47]), size=16, max_len=16, name='System Name', fuzzable=True)
        with s_block("System Description"):
            s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='TLV Type 5', fuzzable=False)
            s_bytes(value=bytes([0x06]), size=1, max_len=1, name='TLV Length 5', fuzzable=False)
            s_bytes(value=bytes([0x53, 0x57, 0x49, 0x54, 0x43, 0x48]), size=6, max_len=6,
                    name='System Description', fuzzable=True)
        with s_block("Capabilities"):
            s_bytes(value=bytes([0x0e]), size=1, max_len=1, name='TLV Type 6', fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name='TLV Length 6', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name='Capabilities', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name='Enabled Capabilities', fuzzable=False)
        with s_block("Management Address"):
            s_bytes(value=bytes([0x10]), size=1, max_len=1, name='TLV Type 7', fuzzable=False)
            s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='TLV Length 7', fuzzable=False)
            s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Address String Length', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Address Subtype', fuzzable=False)
            s_bytes(value=bytes([0xc0, 0xa8, 0x00, 0x02]), size=2, max_len=2, name='Management Address', fuzzable=False)
            s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Interface Subtype', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x0d]), size=4, max_len=4, name='Interface Number', fuzzable=True)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='OID String Length', fuzzable=False)
        with s_block("KYLAND Technology"):
            s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='TLV Type 8', fuzzable=False)
            s_bytes(value=bytes([0x0e]), size=1, max_len=1, name='TLV Length 8', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x1e, 0xcd]), size=2, max_len=2, name='Organization Unique Code', fuzzable=False)
            s_bytes(value=bytes([0xfe]), size=2, max_len=2, name='Unknown Subtype', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x30, 0x02, 0x00, 0x00, 0x00, 0xa1, 0x00, 0x00]), size=10, max_len=10,
                    name='Unknown Subtype Content', fuzzable=True)
        with s_block("End of LLDPDU"):
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='TLV Type 9', fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='TLV Length 9', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, fuzzable=True)

    session.connect(s_get('LLDP'))


if __name__ == "__main__":
    fuzzing_main()
