host_ip = ''
host_port = 6000

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()

def fuzzing_define_proto(session):
    s_initialize(name="rtp")
    with s_block("CON"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='version',fuzzable=False)
        s_bytes(value=bytes([0x63]), size=1, max_len=1, name='Payload.type', fuzzable=False)
        s_bytes(value=bytes([0x5d, 0x52]), size=2, max_len=2, name='rtp.seq', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0xac,0x80]), size=4, max_len=4, name='timestamp', fuzzable=True)
        s_bytes(value=bytes([0x04, 0x3e, 0xee, 0x04]), size=4, max_len=4, name='rtp.ssrc', fuzzable=True)
        s_bytes(value=bytes([0x78]), size=1, max_len=1, name='header', fuzzable=False)
        s_string(value="Payload: eafe52ea689868f91c4e9a64a74d28caf4e25028545eb5b4ef376e191525f3e3190e5cfe…" ,name='payload', fuzzable=True)



    session.connect(s_get("rtp"))
    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
