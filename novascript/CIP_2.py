
host_ip = ''
host_port = 44818

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)

    fuzzing_Start(session=session)
    session.fuzz()

            #start
def fuzzing_Start(session):
    s_initialize(name="Start")
    with s_block("ENIP"):
        s_bytes(value=bytes([0x70,0x00]), size=2, max_len=2, name='cmmand', fuzzable=False)
        s_bytes(value=bytes([0x1c,0x00]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0x01,0x00,0x2a,0x00]), size=4, max_len=4, name='Session_Handle', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='status', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Sender_context', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='options', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Interface_Handle', fuzzable=False)
        s_bytes(value=bytes([0x10,0x00]), size=2, max_len=2, name='Timeout', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x00]), size=2, max_len=2, name='Time_count', fuzzable=True)
        s_bytes(value=bytes([0xa1, 0x00]), size=2, max_len=2, name='Type_ID', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x00]), size=2, max_len=2, name='IC_lenght', fuzzable=False)
        s_bytes(value=bytes([0x22, 0x40,0x95,0xff]), size=4, max_len=4, name='Connection_ID', fuzzable=True)
        s_bytes(value=bytes([0xb1, 0x00]), size=2, max_len=2, name='Type_ID1', fuzzable=False)
        s_bytes(value=bytes([0x08, 0x00]), size=2, max_len=2, name='lenght1', fuzzable=False)
        s_bytes(value=bytes([0xe7, 0x00]), size=2, max_len=2, name='CIP_sequence_count', fuzzable=False)
    with s_block(("CIP")):
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='service', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='request_path_size', fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='path_segment_type', fuzzable=False)
        s_bytes(value=bytes([0x8e]), size=1, max_len=1, name='class', fuzzable=False)
        s_bytes(value=bytes([0x24]), size=1, max_len=1, name='path_segment_type1', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Instance', fuzzable=False)

    session.connect(s_get('Start'))



if __name__ == "__main__":
    fuzzing_main()




















