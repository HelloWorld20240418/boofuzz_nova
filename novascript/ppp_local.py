
interface_port=''
target_mac_str = '01:80:c2:00:00:0e'
target_mac = target_mac_str.split(':')
source_mac_str = 'd4:f5:27:3d:37:58'
source_mac = source_mac_str.split(':')

def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param)
    fuzzing_PPP(session=session)
    session.fuzz()



def fuzzing_PPP(session):
    # PPP LCP协议请求Echo Request，用于建立和配置链路
    s_initialize(name="PPP LCP Request")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination', fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source', fuzzable=False)
        s_bytes(value=bytes([0x88, 0x64]), size=2, max_len=2, name='Type', fuzzable=False)

    with s_block("PPP-over-Ethernet Session"):
        s_bytes(value=bytes([0x11]), size=1,max_len=1, name="Version_Type", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Code", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Session ID", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Payload Length", fuzzable=True)

    with s_block("Point-to-Point Protocol"):
        s_bytes(value=bytes([0xc0, 0x21]), size=2, max_len=2, name="Protocol", fuzzable=False)

    with s_block("PPP Link Control Protocol"):
        s_bytes(value=bytes([0x09]), size=1, max_len=1, name="Code", fuzzable=False)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name="Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=1, max_len=1, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x45, 0x31, 0xc3, 0x55]), size=1, max_len=1, name="Magic Number", fuzzable=True)

    # PPP LCP协议响应Echo Reply，用于建立和配置链路
    s_initialize(name="PPP LCP Reply")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination',
            fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source',
            fuzzable=False)
        s_bytes(value=bytes([0x88, 0x64]), size=2, max_len=2, name='Type', fuzzable=False)

    with s_block("PPP-over-Ethernet Session"):
        s_bytes(value=bytes([0x11]), size=1, max_len=1, name="Version_Type", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Code", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Session ID", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Payload Length", fuzzable=False)

    with s_block("Point-to-Point Protocol"):
        s_bytes(value=bytes([0xc0, 0x21]), size=2, max_len=2, name="Protocol", fuzzable=False)

    with s_block("PPP Link Control Protocol"):
        s_bytes(value=bytes([0x0a]), size=1, max_len=1, name="Code", fuzzable=False)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name="Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=1, max_len=1, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x32, 0x88, 0xaa, 0x78]), size=4, max_len=4, name="Magic Number", fuzzable=True)

    session.connect(s_get('PPP LCP Request'))
    session.connect(s_get('PPP LCP Reply'))

if __name__ == "__main__":
    fuzzing_main()
