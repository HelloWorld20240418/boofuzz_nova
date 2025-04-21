host_ip = ''
host_port = 500

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="ISAKMP")
    with s_block("ISAKMP"):
        s_bytes(value=bytes([0x03,0x26,0xe9,0x00,0x22,0x58,0xbd,0x78]), size=8, max_len=8,name='isakmp.ispi', fuzzable=False)
        s_bytes(value=bytes([0x4a, 0x3f, 0x0b, 0x01, 0x77, 0x83, 0xd0, 0x4b]), size=8, max_len=8,name='responder。isakmp.rspi', fuzzable=False)
        s_bytes(value=bytes([0x2e]), size=1, max_len=2, name='next.payload',fuzzable=True)
        s_bytes(value=bytes([0x20]), size=1, max_len=2, name='version',fuzzable=True)
        s_bytes(value=bytes([0x25]), size=1, max_len=2, name='type',fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=2, name='flags',fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x02]), size=4, max_len=4, name='message.ID', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x50]), size=4, max_len=4, name='length', fuzzable=False)
    with s_block("payload"):
        s_bytes(value=bytes([0x00]), size=1, max_len=2, name='next.payload',fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=2, name='isakmp.criticalpayload',fuzzable=True)
        s_bytes(value=bytes([0x00, 0x34]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0x03, 0x57,0x3f,0x60]), size=4, max_len=4, name='isakmp.enc.iv', fuzzable=True)
        s_bytes(value=bytes([0x68,0xfe,0xdc,0x1d,0x2a,0xf4,0x87,0x0b,0x47,0xcb,0xa7,0xda,0x0b,0x4c,0x21,0x7b,0x8b,0xb3,0xeb,0x7b,0x74,0x8a,0xf3,0x93,0xb4,0xc9,0x65,0x6a,0xe5,0xdc,0xc0,0x89,0x81,0xb6,0xc1,0x2d,0x05,0x1a,0x95,0xa4,0x0b,0x77,0x08,0x76]), size=44, max_len=44, name='data', fuzzable=True)








        session.connect(s_get('ISAKMP'))
if __name__ == "__main__":
            fuzzing_main()