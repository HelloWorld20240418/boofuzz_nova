host_ip = ''
host_port = 8612

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()

def fuzzing_define_proto(session):
    s_initialize(name="Discover")
    with s_block("Discover"):


        s_bytes(value=bytes([0x42,0x4a,0x4e,0x50]), size=4, max_len=4, name='ID', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Type', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='code', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x17, 0xa4]), size=4, max_len=4, name='sequence', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='session_id', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='payload', fuzzable=True)





    session.connect(s_get("Discover"))

    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()