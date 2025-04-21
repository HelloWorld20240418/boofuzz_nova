host_ip = ''
host_port = 34964


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),  nova_session_param=nova_session_param)
    fuzzing_PNDCP(session=session)

    session.fuzz()


def fuzzing_PNDCP(session):
    s_initialize(name="PNDCP")
    with s_block("PNDCP"):
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='data_type', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x10,0x00,0x00]), size=3, max_len=3, name='deta_tepresentation', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='serial_high', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0xa0,0xde,0x97,0x6c,0xd1,0x11,0x82,0x71,0x00,0x01,0x00,0x03,0x01,0x5a]), size=16, max_len=16, name='UUID', fuzzable=True)
        s_bytes(value=bytes([0x01,0x00,0xa0,0xde,0x97,0x6c,0xd1,0x11,0x82,0x71,0x00,0xa0,0x24,0x42,0xdf,0x7d]), size=16, max_len=16, name='PNIO', fuzzable=True)
        s_bytes(value=bytes([0xdb,0xab,0xba,0xec,0x1d,0x00,0x54,0x43,0xb2,0x50,0x0b,0x01,0x63,0x0a,0xba,0xfd]), size=16, max_len=16, name='ACTIVITY', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='SERVER_BOOT_TIME', fuzzable=False)
        s_bytes(value=bytes([0x01,0x00,0x00,0x00]), size=4, max_len=4, name='INTERFACE_VER', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='SEQUENCE_NUM', fuzzable=False)
        s_bytes(value=bytes([0x05,0x00]), size=2, max_len=2, name='OPNUM', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='interface_hint', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='activity_hint', fuzzable=False)
        s_bytes(value=bytes([0x54,0x00]), size=2, max_len=2, name='fragment_len', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='fragment_num', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='auth_proto', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='serial_low', fuzzable=False)
        s_bytes(value=bytes([0x40,0x80,0x00,0x00]), size=4, max_len=4, name='argsmaximum', fuzzable=False)
        s_bytes(value=bytes([0x40,0x00,0x00,0x00]), size=4, max_len=4, name='argslength', fuzzable=False)
        s_bytes(value=bytes([0x40,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00]), size=12, max_len=12, name='argslength2', fuzzable=False)
        s_bytes(value=bytes([0x00,0x09]), size=2, max_len=2, name='blocktype', fuzzable=False)
        s_bytes(value=bytes([0x00,0x3c]), size=2, max_len=2, name='blocklength', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='blockversion', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='blockversionlow', fuzzable=False)
        s_bytes(value=bytes([0x00,0x0a]), size=2, max_len=2, name='seqnumber', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,]), size=16, max_len=16, name='aruuid', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='api', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='slotnumber', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='subslotnumber', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='pad', fuzzable=False)
        s_bytes(value=bytes([0xf8,0x40]), size=2, max_len=2, name='index', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x80,0x00]), size=4, max_len=4, name='recorddatalength', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=16, max_len=16, name='targetaruuid', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=8, max_len=8, name='padding', fuzzable=True)


    session.connect(s_get('PNDCP'))

if __name__ == "__main__":
    fuzzing_main()