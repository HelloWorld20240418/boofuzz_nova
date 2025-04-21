host_ip = ''
host_port = 646


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_LDP_SESSION(session=session)

    session.fuzz()


def fuzzing_LDP_SESSION(session):
    s_initialize(name="LDP_SESSION")
    with s_block("LDP_SESSION"):
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x1e]), size=2, max_len=2, name='pdu_length', fuzzable=False)
        s_bytes(value=bytes([0x09, 0x09,0x09,0x09]), size=4, max_len=4, name='lsr', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='label_spaceID', fuzzable=False)
        s_bytes(value=bytes([0x01,0x00]), size=2, max_len=2, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x14]), size=2, max_len=2, name='message_length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x02, 0xa6,0xbe]), size=4, max_len=4, name='lsr2', fuzzable=False)
        s_bytes(value=bytes([0x04,0x00, 0x00,0x04,0x00,0x0f,0x00,0x00]), size=8, max_len=8, name='common_hello', fuzzable=True)
        s_bytes(value=bytes([0x04, 0x00]), size=2, max_len=2, name='message_type2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name='message_length2', fuzzable=False)
        s_bytes(value=bytes([0x09, 0x09,0x09,0x09]), size=4, max_len=4, name='IPV4', fuzzable=True)



    session.connect(s_get('LDP_SESSION'))

if __name__ == "__main__":
    fuzzing_main()