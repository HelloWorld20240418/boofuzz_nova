host_ip = ''
host_port = 2404


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_ICCP(session=session)

    session.fuzz()


def fuzzing_ICCP(session):
    s_initialize(name="ICCP")
    with s_block("ICCP_ip"):
        s_bytes(value=bytes([0x68]), size=1, max_len=1, name='START', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='APDULEN', fuzzable=True)
        s_bytes(value=bytes([0x07,0x00,0x00,0x00]), size=4, max_len=4, name='TYPE', fuzzable=True)

    session.connect(s_get('ICCP'))

if __name__ == "__main__":
    fuzzing_main()