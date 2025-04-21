
host_ip = ''
host_port = 646


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_LDP_SESSION(session=session)

    session.fuzz()


def fuzzing_LDP_SESSION(session):
    s_initialize(name="LDP_SESSION")
    with s_block("LDP_SESSION"):
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x20]), size=2, max_len=2, name='pdu_length', fuzzable=False)
        s_bytes(value=bytes([0x09, 0x09,0x09,0x09]), size=4, max_len=4, name='lsr', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='label_spaceID', fuzzable=False)
        s_bytes(value=bytes([0x02,0x00]), size=2, max_len=2, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x16]), size=2, max_len=2, name='message_length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x02, 0xa6,0xf0]), size=4, max_len=4, name='lsr2', fuzzable=False)
        s_bytes(value=bytes([0x05, 0x00]), size=2, max_len=2, name='message_type2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0e]), size=2, max_len=2, name='message_length2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='session_version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x2d]), size=2, max_len=2, name='ldp.msg.tlv.sess.ka', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='ldp.msg.tlv.sess.advbit', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='ldp.msg.tlv.sess.pvlim', fuzzable=False)
        s_bytes(value=bytes([0x10, 0x00]), size=2, max_len=2, name='ldp.msg.tlv.sess.mxpdu', fuzzable=False)
        s_bytes(value=bytes([0x08,0x08, 0x08,0x08]), size=4, max_len=4, name='ldp.msg.tlv.sess.lsr2', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='ldp.msg.tlv.sess.rxls', fuzzable=True)








    session.connect(s_get('LDP_SESSION'))

if __name__ == "__main__":
    fuzzing_main()