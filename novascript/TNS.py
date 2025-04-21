host_ip = ''
host_port = 1521


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_TNS(session=session)

    session.fuzz()


def fuzzing_TNS(session):
    s_initialize(name="TNS")
    with s_block("TNS"):
        s_bytes(value=bytes([0x00,0x34]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='CHECKSUM', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='TPYE',fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='BYTE',fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='HEADER_CHECKSUM', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='data_flag', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='DATAID',fuzzable=True)
        s_bytes(value=bytes([0x69,0x03,0x69,0x03,0x03,0x15,0x06,0x01,0x01,0x01,0x05,0x01,0x01,0x02,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x3f,0x0f,0x03,0x06,0x03,0x00,0x02,0x02,0x01,0x80,0x00,0x00,0x00,0x3c,0x3c,0x3c,0x80,0x00,0x00,0x00]), size=41, max_len=41, name='data_id',fuzzable=True)


    session.connect(s_get('TNS'))

if __name__ == "__main__":
    fuzzing_main()