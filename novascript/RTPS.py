

host_ip = ''
host_port = 36410


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_RTPS(session=session)

    session.fuzz()


def fuzzing_RTPS(session):
    s_initialize(name="RTPS")
    with s_block("RTPS"):
        s_bytes(value=bytes([0x52,0x54,0x50,0x53]), size=4, max_len=4, name='MAGIC', fuzzable=False)
        s_bytes(value=bytes([0x02,0x01]), size=2, max_len=2, name='protocol.version', fuzzable=False)
        s_bytes(value=bytes([0x01,0x01]), size=2, max_len=2, name='rtps.vendorId', fuzzable=True)
        s_bytes(value=bytes([0x4e,0x44,0x44,0x53,0x50,0x49,0x4e,0x47]), size=8, max_len=8, name='text', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='pad', fuzzable=True)


    session.connect(s_get('RTPS'))

if __name__ == "__main__":
    fuzzing_main()