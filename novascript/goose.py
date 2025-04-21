interface_port = ''

def fuzzing_main():
    session = Session(target=Target(connection=RawL2SocketConnection(interface=interface_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="GOOSE")
    with s_block("Ethernet II"):
        s_bytes(value=bytes([0xa1, 0xa0, 0xf4, 0x08, 0x2f, 0x77]), size=6, max_len=6, name='Destination',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0xa0, 0xf4, 0x08, 0x2f, 0x77]), size=6, max_len=6, name='Source', fuzzable=False)
        s_bytes(value=bytes([0x88, 0xb8]), size=2, max_len=2, name='Type', fuzzable=False)
    with s_block("GOOSE"):
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='APPID', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x91]), size=2, max_len=2, name='Length', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Reserved 1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Reserved 2 ', fuzzable=False)
        s_bytes(value=bytes([0x61, 0x81, 0x86]), size=3, max_len=3, fuzzable=False)
        with s_block("goosePdu"):
            s_bytes(value=bytes([0x80, 0x1a]), size=2, max_len=2, fuzzable=False)
            s_bytes(
                value=bytes([0x47, 0x45, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x46, 0x36, 0x35, 0x30, 0x2f, 0x4c, 0x4c,
                             0x4e, 0x30, 0x24, 0x47, 0x4f, 0x24, 0x67, 0x63, 0x62, 0x30, 0x31]),
                size=26, max_len=26, name='gocbRef', fuzzable=True)
            s_bytes(value=bytes([0x81, 0x03]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x00, 0x9c, 0x40]), size=3, max_len=3, name='timeAllowedtoLive', fuzzable=False)
            s_bytes(value=bytes([0x82, 0x18]), size=2, max_len=2, fuzzable=False)
            s_bytes(
                value=bytes([0x47, 0x45, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x46, 0x36, 0x35, 0x30, 0x2f, 0x4c, 0x4c,
                             0x4e, 0x30, 0x24, 0x47, 0x4f, 0x4f, 0x53, 0x45, 0x31]), size=24, max_len=24, name='datSet',
                fuzzable=True)
            s_bytes(value=bytes([0x83, 0x0b]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x43, 0x36, 0x35, 0x30, 0x5f, 0x47, 0x4f, 0x4f, 0x53, 0x45, 0x31]), size=11,
                    max_len=11, name='goID', fuzzable=True)
            s_bytes(value=bytes([0x84, 0x08]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x38, 0x6e, 0xbb, 0xf3, 0x42, 0x17, 0x28, 0x0a]), size=8, max_len=8, name='t')
            s_bytes(value=bytes([0x85, 0x01]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='stNum', fuzzable=False)
            s_bytes(value=bytes([0x86, 0x01]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='sqNum', fuzzable=False)
            s_bytes(value=bytes([0x87, 0x01]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='simulation', fuzzable=False)
            s_bytes(value=bytes([0x88, 0x01]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='confRev', fuzzable=False)
            s_bytes(value=bytes([0x89, 0x01]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='ndsCom', fuzzable=False)
            s_bytes(value=bytes([0x8a, 0x01]), size=2, max_len=2, fuzzable=False)
            s_bytes(value=bytes([0x08]), size=1, max_len=1, name='numDatSetEntries', fuzzable=False)
            s_bytes(value=bytes([0xab, 0x20]), size=2, max_len=2, fuzzable=False)
            s_bytes(
                value=bytes([0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00,
                             0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03,
                             0x00, 0x00]), size=32, max_len=32, name='allData', fuzzable=True)

    session.connect(s_get('GOOSE'))


if __name__ == "__main__":
    fuzzing_main()
