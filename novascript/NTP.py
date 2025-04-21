
host_ip = ''
host_port = 123

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="NTP")
    with s_block("ntp"):
        s_bytes(value=bytes([0Xe3]), size=1, max_len=1, name='flags', fuzzable=True)
        s_bytes(value=bytes([0X00]), size=1, max_len=1, name='peer_clock_stratum', fuzzable=True)
        s_bytes(value=bytes([0X03]), size=1, max_len=1, name='peer_polling_interval', fuzzable=True)
        s_bytes(value=bytes([0X00]), size=1, max_len=1, name='peer_clock_precision', fuzzable=True)
        s_bytes(value=bytes([0X00, 0X00,0x00,0x00]), size=4, max_len=4, name='Root_delay', fuzzable=True)
        s_bytes(value=bytes([0X00, 0X00, 0x00, 0x00]), size=4, max_len=4, name='Root_dispersion', fuzzable=True)
        s_bytes(value=bytes([0X00, 0X00, 0x00, 0x00]), size=4, max_len=4, name='reference_ID', fuzzable=True)
        s_bytes(value=bytes([0X00, 0X00, 0x00, 0x00,0x00,0x00,0x00,0x00]), size=8, max_len=8, name='Reference_timestamp', fuzzable=True)
        s_bytes(value=bytes([0X00, 0X00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8,name='origin_timestamp', fuzzable=True)
        s_bytes(value=bytes([0X00, 0X00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8,name='Receive_timestamp', fuzzable=True)
        s_bytes(value=bytes([0Xe6, 0X77, 0x5b, 0xef, 0x71, 0x5f, 0xa7, 0xff]), size=8, max_len=8,name='transmit_timestamp', fuzzable=True)
       





        session.connect(s_get('NTP'))
if __name__ == "__main__":
    fuzzing_main()