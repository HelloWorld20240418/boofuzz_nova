
host_ip = ''
host_port = 5683

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()

def fuzzing_define_proto(session):
    s_initialize(name="COAP")
    with s_block("CON"):
        s_random(value=bytes([0x44]),name='version',fuzzable=True)
        s_group("Code",[bytes([0x01]), bytes([0x02]),bytes([0x03]),bytes([0x04])])
        s_bytes(value=bytes([0x0c,0x48]), size=2, max_len=2, name='Message_ID', fuzzable=False)
        s_bytes(value=bytes([0xd1,0x97,0x96,0xcd]), size=4, max_len=4, name='Token', fuzzable=False)
        s_bytes(value=bytes([0xc1, 0x3c]), size=2, max_len=2, name='OPT_desc', fuzzable=True)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='end_of_options_marker', fuzzable=True)
        s_bytes(value=bytes([0x3b, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff]), size=9, max_len=9, name='payload', fuzzable=True)





    session.connect(s_get("COAP"))

    session.fuzz()


if __name__ == "__main__":
    fuzzing_main()
