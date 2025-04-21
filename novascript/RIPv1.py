host_ip = ''
host_port = 520

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()

def fuzzing_define_proto(session):
    s_initialize(name="RIP")
    with s_block("RIP"):
        s_bytes(value=bytes([0x01]),name='command',fuzzable=False)
        s_group("Code", [bytes([0x01])])
        s_bytes(value=bytes([0x00,0x00]), name='address.not.specified.metric', size=2, max_len=2, fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='address.family', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=14, max_len=14, name='address.not.specified.metric.header', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x16]), size=4, max_len=4, name=',metric', fuzzable=True)



    session.connect(s_get("RIP"))

    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()