host_ip = ''
host_port = 53

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="DNS")
    with s_block("query"):
        s_bytes(value=bytes([0X00,0X20]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0X78, 0X64]), size=2, max_len=2, name='Transaction_ID', fuzzable=False)
        s_bytes(value=bytes([0X01, 0X00]), size=2, max_len=2, name='flags', fuzzable=False)
        s_bytes(value=bytes([0X00, 0X01]), size=2, max_len=2, name='questions', fuzzable=False)
        s_bytes(value=bytes([0X00, 0X00]), size=2, max_len=2, name='Answer_RRS', fuzzable=False)
        s_bytes(value=bytes([0X00, 0X00]), size=2, max_len=2, name='Authority_RRS', fuzzable=False)
        s_bytes(value=bytes([0X00, 0X00]), size=2, max_len=2, name='Additional_RRS', fuzzable=False)
        s_bytes(value=bytes([0X03,0x77,0x77,0x07,0x06,0x76,0x65,0x6e,0x64,0x6f,0x72,0x03,0x63,0x6f,0x6d,0x00]), size=16, max_len=16, name='Name', fuzzable=True)
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='Type', fuzzable=True)
        s_bytes(value=bytes([0X00, 0X01]), size=2, max_len=2, name='Class', fuzzable=True)





        session.connect(s_get('DNS'))
if __name__ == "__main__":
            fuzzing_main()