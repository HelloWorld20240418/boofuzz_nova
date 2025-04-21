
host_ip = ''
host_port = 5432

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()

def fuzzing_define_proto(session):
    s_initialize(name="PostgreSQL")
    with s_block("PostgreSQL"):
        s_bytes(value=bytes([0x00, 0x00,0x00, 0x26]), size=4, max_len=4, name='length', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x03]), size=2, max_len=2, name='protocol.major.version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='2protocol.major.version', fuzzable=False)
        s_bytes(value=bytes([0x75, 0x73,0x65, 0x72,0x00]), size=5, max_len=5, name='name', fuzzable=False)
        s_bytes(value=bytes([0x75, 0x73,0x65, 0x72,0x00,0x00]), size=6, max_len=6, name='value', fuzzable=True)
        s_bytes(value=bytes([0x64,0x61,0x74,0x61,0x62,0x61,0x73,0x65,0x00]), size=9, max_len=9, name='dataname', fuzzable=False)
        s_bytes(value=bytes([0x4d,0x79,0x73,0x71,0x6c,0x5f,0x64,0x62,0x00]), size=9, max_len=9, name='datavalue', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='0', fuzzable=False)



    session.connect(s_get("PostgreSQL"))

    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
