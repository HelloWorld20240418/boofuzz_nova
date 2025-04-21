host_ip = ''
host_port = 47808

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_Confirmed_REQ(session=session)
    session.fuzz()


def fuzzing_Confirmed_REQ(session):
    s_initialize(name="Confirmed_REQ")
    with s_block("BACnet_Virtual_link"):
        s_bytes(value=bytes([0x81]),  name='Type', fuzzable=False)
        s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='function', fuzzable=False)
        s_bytes(value=bytes([0x00,0x11]),size=2, max_len=2, name='BVLC_length', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='control', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='APDU_Type', fuzzable=False)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='MRSA', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Invoke_ID', fuzzable=False)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='Service_choice', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='contxt_Tag', fuzzable=True)
        s_bytes(value=bytes([0x02,0x3f,0xff,0xff]), size=4, max_len=4, name='object_type', fuzzable=True)
        s_bytes(value=bytes([0x19]), size=1, max_len=1, name='contxt_Tag1', fuzzable=True)
        s_bytes(value=bytes([0x4b]), size=1, max_len=1, name='Property_Identifier', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='padding', fuzzable=True)

    session.connect(s_get('Confirmed_REQ'))
if __name__ == "__main__":
    fuzzing_main()