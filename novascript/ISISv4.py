
interface_port=''
target_mac_str = '01:80:c2:00:00:14'
target_mac = target_mac_str.split(':')
source_mac_str = '01:08:c2:00:00:14'
source_mac = source_mac_str.split(':')
src_ip = []
def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)),nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="ISIS_V4_HELLO")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination',
            fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source',
            fuzzable=False)
        s_bytes(value=bytes([0x05, 0xdc]), size=2, max_len=2, name='Length', fuzzable=False)
    with s_block("Logical-Link Control"):
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='DSAP', fuzzable=False)
        s_bytes(value=bytes([0xfe]), size=1, max_len=1, name='SSAP', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Control field', fuzzable=False)
    with s_block("ISO_10589_ISIS"):
        s_bytes(value=bytes([0x83]), size=1, max_len=1, name='Intradomain Routing Protocol Discriminator', fuzzable=False)
        s_bytes(value=bytes([0x1b]), size=1, max_len=1, name='Length Indicator', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Version/Protocol ID Extension', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='ID_length', fuzzable=False)
        s_bytes(value=bytes([0x0f]), size=1, max_len=1, name='Type: L1_HELLO', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Maximum_Area_Addresses', fuzzable=False)
    with s_block("ISIS_HELLO"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Circuit type: Level 1 and 2 ', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x01]), size=6, max_len=6, name='SystemID {Sender of PDU}', fuzzable=False)
        s_bytes(value=bytes([0x00,0x1e]), size=2, max_len=2, name='Holding_timer', fuzzable=False)
        s_bytes(value=bytes([0x05,0xd9]), size=2, max_len=2, name='PDU_length', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='Proiority', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x01,0x02]), size=7, max_len=7, name='SystemID {Designated IS}', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='TYPE', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Length', fuzzable=False)
        s_bytes(value=bytes([0x03, 0x49,0x00,0x01]), size=4, max_len=4, name='Area_address', fuzzable=False)
        s_bytes(value=bytes([0x84]), size=1, max_len=1, name='TYPE_ip', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Length_ip', fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='ip_address', fuzzable=False)
        s_bytes(value=bytes([0x81]), size=1, max_len=1, name='Protocols_Supported_TYPE', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Protocols_Supported_Length', fuzzable=False)
        s_bytes(value=bytes([0xcc]), size=1, max_len=1, name='Protocols_Supported_address', fuzzable=False)
        s_bytes(value=bytes([0xd3]), size=1, max_len=1, name='Restart_signaling_TYPE', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Restart_signaling_Length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00]), size=3, max_len=3, name='Restart_signaling_address', fuzzable=False)
        s_bytes(value=bytes([0xe5]), size=1, max_len=1, name='Multi_Topology_TYPE', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Multi_Topology_Length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='IPV4_unicast_Tppology', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Padding_Type1', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Padding_Length1', fuzzable=False)
        s_string("0000",size=255,max_len=255,name='data1')
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Padding_Type2', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Padding_Length2', fuzzable=False)
        s_string("0000",size=255,max_len=255,name='data2')
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Padding_Type3', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Padding_Length3', fuzzable=False)
        s_string("0000",size=255,max_len=255,name='data3')
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Padding_Type4', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Padding_Length4', fuzzable=False)
        s_string("0000",size=255,max_len=255,name='data4')
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Padding_Type5', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Padding_Length5', fuzzable=False)
        s_string("0000",size=255,max_len=255,name='data5')
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Padding_Type6', fuzzable=False)
        s_bytes(value=bytes([0x9f]), size=1, max_len=1, name='Padding_Length6', fuzzable=False)
        s_string("0000",size=159,max_len=159,name='data6')


    session.connect(s_get('ISIS_V4_HELLO'))


if __name__ == "__main__":
    fuzzing_main()