
host_ip = ''
host_port = 102

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_tpkt(session=session)
    session.fuzz()
def fuzzing_tpkt(session):
    s_initialize(name="tpkt INVITE")
    with s_block("tpkt"):
        s_bytes(value=bytes([0x80, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x44, 0xa4, 0xde, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]), size=32, max_len=32, name='tpkt', fuzzable=True)

    session.connect(s_get("tpkt INVITE"))
if __name__ == "__main__":
    fuzzing_main()
