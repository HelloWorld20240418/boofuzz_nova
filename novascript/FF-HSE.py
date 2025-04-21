host_ip = ''
host_port = 3622

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_FF(session=session)
    session.fuzz()
def fuzzing_FF(session):
    s_initialize(name="FF")
    with s_block("FF"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='FDA_message_version', fuzzable=False)
        s_bytes(value=bytes([0xa0]), size=1, max_len=1, name='options', fuzzable=True)
        s_bytes(value=bytes([0x10]), size=1, max_len=1, name='service_ID', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='service', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='FDA_Address', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x64]), size=4, max_len=4, name='message_length', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Device_Index', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='number_of_network_interfaces', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Transmission_INterface', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0xea, 0x60]), size=4, max_len=4, name='Diagnostic_message_interval', fuzzable=True)
        s_bytes(value=bytes([0x57,0x75,0x72,0x6c,0x64,0x74,0x65,0x63,0x68,0x20,0x31,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20
                             ,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20]), size=32, max_len=32, name='PD_tag', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Duplicate_detection_state', fuzzable=True)
        s_bytes(value=bytes([0x00,0x02]), size=2, max_len=2, name='number_of_interface_statuses', fuzzable=True)
        s_bytes(value=bytes([0x7f,0xff,0xf7,0xff]), size=4, max_len=4, name='Interface_Atoa_status', fuzzable=True)
        s_bytes(value=bytes([0x75, 0x57, 0x7f, 0xff]), size=4, max_len=4, name='Interface_Atoa_status1', fuzzable=True)
        s_bytes(value=bytes([0x7f, 0xff, 0xf7, 0xff]), size=4, max_len=4, name='Interface_Btoa_status', fuzzable=True)
        s_bytes(value=bytes([0x75, 0x57, 0x7f, 0xff]), size=4, max_len=4, name='Interface_Btoa_status1', fuzzable=True)
        s_bytes(value=bytes([0x7f, 0xff, 0xf7, 0xff]), size=4, max_len=4, name='Interface_AtoB_status', fuzzable=True)
        s_bytes(value=bytes([0x75, 0x57, 0x7f, 0xff]), size=4, max_len=4, name='Interface_AtoB_status1', fuzzable=True)
        s_bytes(value=bytes([0x7f, 0xff, 0xf7, 0xff]), size=4, max_len=4, name='Interface_BtoB_status', fuzzable=True)
        s_bytes(value=bytes([0x75, 0x57, 0x7f, 0xff]), size=4, max_len=4, name='Interface_BtoB_status1', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x01]), size=4, max_len=4, name='Message_number', fuzzable=True)
        s_bytes(value=bytes([0x41, 0x01, 0x06, 0x00,0x20,0x20,0x20,0x20]), size=8, max_len=8, name='TIME_stamp', fuzzable=True)


    session.connect(s_get('FF'))


if __name__ == "__main__":
    fuzzing_main()