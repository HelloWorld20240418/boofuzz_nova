
interface_port=''
target_mac_str = '01:80:c2:00:00:0e'
target_mac = target_mac_str.split(':')
source_mac_str = 'd4:f5:27:3d:37:58'
source_mac = source_mac_str.split(':')

def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)),nova_session_param=nova_session_param)
    fuzzing_PPPOE(session=session)
    session.fuzz()



def fuzzing_PPPOE   (session):
    # PPPoE Client广播发送一个PADI报文，在此报文中包含PPPoE Client想要得到的服务类型信息。
    s_initialize(name="PPPOE_PADI")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination', fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source', fuzzable=False)
        s_bytes(value=bytes([0x88, 0x63]), size=2, max_len=2, name='Type', fuzzable=False)

    with s_block("PPP-over-Ethernet Discovery"):
        s_bytes(value=bytes([0x11]), size=1,max_len=1, name="Version_Type", fuzzable=False)
        s_bytes(value=bytes([0x09]), size=1, max_len=1, name="Code", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Session ID", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name="Payload Length", fuzzable=False)
        s_bytes(value=bytes([0x01, 0x01, 0x00, 0x00]), size=4, max_len=4, name="PPPoE Tags", fuzzable=True)


    # 所有的PPPoE Server收到PADI报文之后，将其中请求的服务与自己能够提供的服务进行比较，如果可以提供，则单播回复一个PADO报文
    s_initialize(name="PPPOE_PADO")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination', fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source', fuzzable=False)
        s_bytes(value=bytes([0x88, 0x63]), size=2, max_len=2, name='Type', fuzzable=False)

    with s_block("PPP-over-Ethernet Discovery"):
        s_bytes(value=bytes([0x11]), size=1,max_len=1, name="Version_Type", fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name="Code", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Session ID", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x23]), size=2, max_len=2, name="Payload Length", fuzzable=False)
        with s_block("PPPoE Tags"):
            s_bytes(value=bytes([0x72, 0x2D, 0x61, 0x6C, 0x31, 0x32, 0x31]), size=7, max_len=7, name="AC-Name", fuzzable=False)
            s_string(value="bebcb53c10b32769a8661c36a45d8720", size=32, max_len=32, name="AC-cookie", fuzzable=True)

    #PPPoE Client选择最先收到的PADO报文对应的PPPoE Server做为自己的PPPoE Server，并单播发送一个PADR报文
    s_initialize(name="PPPOE_PADR")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination', fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source', fuzzable=False)
        s_bytes(value=bytes([0x88, 0x63]), size=2, max_len=2, name='Type', fuzzable=False)

    with s_block("PPP-over-Ethernet Discovery"):
        s_bytes(value=bytes([0x11]), size=1,max_len=1, name="Version_Type", fuzzable=False)
        s_bytes(value=bytes([0x19]), size=1, max_len=1, name="Code", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Session ID", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x18]), size=2, max_len=2, name="Payload Length", fuzzable=False)
        with s_block("PPPoE Tags"):
            s_string(value="bebcb53c10b32769a8661c36a45d8720", size=32, max_len=32, name="AC-cookie", fuzzable=True)

    #PPPoE Server产生一个唯一的会话ID（Session ID），标识和PPPoE Client的这个会话，通过发送一个PADS报文把会话ID发送给PPPoE Client，从而建立会话，并进入PPPoE Session阶段。
    s_initialize(name="PPPOE_PADS")
    with s_block("Ethernet II"):
        s_bytes(
            value=bytes([int(target_mac[0], 16), int(target_mac[1], 16), int(target_mac[2], 16), int(target_mac[3], 16),
                         int(target_mac[4], 16), int(target_mac[5], 16)]), size=6, max_len=6, name='Destination', fuzzable=False)
        s_bytes(
            value=bytes([int(source_mac[0], 16), int(source_mac[1], 16), int(source_mac[2], 16), int(source_mac[3], 16),
                         int(source_mac[4], 16), int(source_mac[5], 16)]), size=6, max_len=6, name='Source', fuzzable=False)
        s_bytes(value=bytes([0x88, 0x63]), size=2, max_len=2, name='Type', fuzzable=False)

    with s_block("PPP-over-Ethernet Discovery"):
        s_bytes(value=bytes([0x11]), size=1,max_len=1, name="Version_Type", fuzzable=False)
        s_bytes(value=bytes([0x65]), size=1, max_len=1, name="Code", fuzzable=False)
        s_bytes(value=bytes([0x18, 0xb2]), size=2, max_len=2, name="Session ID", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name="Payload Length", fuzzable=False)
        s_bytes(value=bytes([0x01, 0x01, 0x00, 0x00]), size=4, max_len=4, name='PPPoE Tags', fuzzable=True)

    session.connect(s_get('PPPOE_PADI'))
    session.connect(s_get('PPPOE_PADO'))
    session.connect(s_get('PPPOE_PADR'))
    session.connect(s_get('PPPOE_PADS'))

if __name__ == "__main__":
    fuzzing_main()
