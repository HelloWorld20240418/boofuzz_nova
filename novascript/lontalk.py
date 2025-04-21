host_ip = ''
host_port = 1628


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_LONTALK(session=session)

    session.fuzz()


def fuzzing_LONTALK(session):
    s_initialize(name="LONTALK")
    with s_block("LONTALK_ip"):
        s_bytes(value=bytes([0x00,0x20]), size=1, max_len=1, name='packet_length', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='packet_type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='header_size', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='code', fuzzable=False)
        s_bytes(value=bytes([0x6b,0x8b,0x45,0x67]), size=4, max_len=4, name='session_id', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='sequence_number', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='time_stamp', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='ppdu', fuzzable=False)
        s_bytes(value=bytes([0x09]), size=1, max_len=1, name='NPDU', fuzzable=False)
        s_bytes(value=bytes([0x01,0xaa,0x01,0xa9]), size=4, max_len=4, name='address_type', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='domain', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='TPDU', fuzzable=False)
        s_bytes(value=bytes([0x81,0x0d]), size=2, max_len=2, name='NETWORK', fuzzable=True)
        s_bytes(value=bytes([0x00,0xca]), size=2, max_len=2, name='data', fuzzable=True)

    session.connect(s_get('LONTALK'))

if __name__ == "__main__":
    fuzzing_main()