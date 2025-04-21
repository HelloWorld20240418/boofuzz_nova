
interface_port = ''

def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="ARP")
    with s_block("Ethernet II"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), size=6, max_len=6, name='Destination',
                fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x11, 0x01, 0x02, 0x02]), size=6, max_len=6, name='Source', fuzzable=True)
        s_bytes(value=bytes([0x08, 0x06]), size=2, max_len=2, name='Type', fuzzable=False)
    with s_block("ARP"):
        s_bytes(value=bytes([0x00,0X01]), size=2, max_len=2, name='Hardware_type',
                fuzzable=False)
        s_bytes(value=bytes([0x08,0x00]), size=2, max_len=2, name='Protocol_type', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Hardware_size', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Protocol_size', fuzzable=False)
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='Opcode', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x11, 0x01, 0x02, 0x02]), size=6, max_len=6, name='sender_MAC_address', fuzzable=False)
        s_bytes(value=bytes([ 0x11, 0x01, 0x02, 0x02]), size=4, max_len=4, name='sender_IP_address',fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=6, max_len=6, name='Target_MAC_address', fuzzable=False)
        s_bytes(value=bytes([ 0x11, 0x01, 0x01, 0x64]), size=4, max_len=4, name='Target_IP_address',fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00,0x00,0x00, 0x00, 0x00, 0x00,0x00,
                             0x00, 0x00, 0x00, 0x00,0x00,0x00, 0x00, 0x00,]), size=18, max_len=18, name='padding', fuzzable=True)
    session.connect(s_get('ARP'))

if __name__ == "__main__":
    fuzzing_main()





