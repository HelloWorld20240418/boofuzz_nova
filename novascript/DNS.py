
host_ip = ''
host_port = 53

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="DNS")
    with s_block("query"):
        s_bytes(value=bytes([0x00,0x2b]), size=2, max_len=2, name='Transaction_ID', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='flags', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Qustions', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Answer_RRS', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Authority_RRS', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Additional_RRS', fuzzable=True)
        s_bytes(value=bytes([0x02,0x75,0x73,0x04,0x70,0x6f,0x6f,0x6c,0x03,0x6e,0x74,0x70,0x03,0x6f,0x72,0x67,0x00]), size=17, max_len=17, name='Name', fuzzable=True)
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='Type', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Class', fuzzable=True)


        session.connect(s_get('DNS'))
if __name__ == "__main__":
    fuzzing_main()