host_ip = ''
host_port = 5094


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_hart(session=session)

    session.fuzz()


def fuzzing_hart(session):
    s_initialize(name="hart")
    with s_block("hart_ip"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='version', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='message_ID', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='status', fuzzable=False)
        s_bytes(value=bytes([0x00,0x02]), size=2, max_len=2, name='number', fuzzable=True)
        s_bytes(value=bytes([0x00,0x0d]), size=2, max_len=2, name='message_length', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='HOST_TYPE', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x75,0x30]), size=4, max_len=4, name='INACTIVITY_CLOSE_TIMER', fuzzable=True)

    session.connect(s_get('hart'))

if __name__ == "__main__":
    fuzzing_main()