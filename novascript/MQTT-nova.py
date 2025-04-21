host_ip = ''
host_port = 1883

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="MQTT")
    with s_block("Connect_command"):
        s_bytes(value=bytes([0x10]), size=1, max_len=1, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0x2c]), size=1, max_len=1, name='Msg_Len', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name='Protocol_Name_Length', fuzzable=False)
        s_bytes(value=bytes([0x4d,0x51,0x54,0x54]), size=4, max_len=4, name='Protocol_Name', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Connect_Flags', fuzzable=False)
        s_bytes(value=bytes([0x00,0x1e]), size=2, max_len=2, name='Keep_Alive', fuzzable=False)
        s_bytes(value=bytes([0x00,0x05]), size=2, max_len=2, name='Client_id_length', fuzzable=False)
        s_bytes(value=bytes([0x35,0x33,0x30,0x38,0x35]), size=5, max_len=5, name='Client_id', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0b]), size=2, max_len=2, name='Will_Topic_length', fuzzable=False)
        s_bytes(value=bytes([0x2f,0x54,0x65,0x73,0x74,0x20,0x54,0x6f,0x70,0x69,0x63]), size=11, max_len=11, name='Will_topic1', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x0c]), size=2, max_len=2, name='Will_Message_Length', fuzzable=False)
        s_bytes(value=bytes([0x54, 0x65,0x73,0x74,0x20,0x4d,0x65,0x73,0x73,0x61,0x67,0x65]), size=12, max_len=12, name='Will_message1', fuzzable=True)
    s_initialize(name="publish_message")
    with s_block("publish_message"):
        s_bytes(value=bytes([0x30]), size=1, max_len=1, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0x16]), size=1, max_len=1, name='Msg_Len', fuzzable=False)
        s_bytes(value=bytes([0x00,0x0b]), size=2, max_len=2, name='Topic_length', fuzzable=False)
        s_bytes(value=bytes([0x2f,0x54,0x65,0x73,0x74,0x20,0x54,0x6f,0x70,0x69,0x63]), size=11, max_len=11, name='Topic', fuzzable=True)
        s_bytes(value=bytes([0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x20,0x31]), size=9, max_len=9, name='Message', fuzzable=True)
    s_initialize(name="publish_message_id2")
    with s_block("publish_message_id2"):
        s_bytes(value=bytes([0x32]), size=1, max_len=1, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0x18]), size=1, max_len=1, name='Msg_Len', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0b]), size=2, max_len=2, name='Topic_length', fuzzable=False)
        s_bytes(value=bytes([0x2f, 0x54, 0x65, 0x73, 0x74, 0x20, 0x54, 0x6f, 0x70, 0x69, 0x63]), size=11, max_len=11,
                name='Topic', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name='Message_identifier', fuzzable=False)
        s_bytes(value=bytes([0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x32]), size=9, max_len=9, name='Message',
                fuzzable=True)
    s_initialize(name="Disconnect_Req")
    with s_block("Disconnect_Req"):
        s_bytes(value=bytes([0xe0]), size=1, max_len=1, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Msg_Len', fuzzable=True)



        session.connect(s_get('MQTT'))
        session.connect(s_get("MQTT"), s_get("publish_message"))
        session.connect(s_get("publish_message"), s_get("publish_message_id2"))
        session.connect(s_get("publish_message_id2"), s_get("Disconnect_Req"))
if __name__ == "__main__":
            fuzzing_main()