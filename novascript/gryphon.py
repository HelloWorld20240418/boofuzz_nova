host_ip = ''
host_port = 7000


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_Command_request(session=session)

    session.fuzz()


def fuzzing_Command_request(session):
    s_initialize(name="Command_request")
    with s_block("DG"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Source', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_client_id', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Destination', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_client_id', fuzzable=False)
        s_bytes(value=bytes([0x00,0x34]), size=2, max_len=2, name='Data_length', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Frame_type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        #boby
        s_bytes(value=bytes([0x50]), size=1, max_len=1, name='Command', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Context', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00
                             ,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00]), size=16, max_len=16, name='Username', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00
                             ,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                                , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                             ]), size=32, max_len=32, name='Password', fuzzable=True)
    session.connect(s_get('Command_request'))

if __name__ == "__main__":
    fuzzing_main()