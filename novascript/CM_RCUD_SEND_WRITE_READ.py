
host_ip = ''
host_port = 4791

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    RC_SEND_READ_WRITE(session)

    session.fuzz()

def RC_SEND_READ_WRITE(session):
    s_initialize(name="Send_Only_QP_InfiniBand")
    with s_block("Base_Transport_Header"):
        # 0x04代表RC_SEND_ONLY;
        # 0x0c代表RC_READ_REQUEST;
        # 0x0d代表RC_READ_RESPONSE_FIRST;
        # 0x0e代表RC_READ_RESPONSE_MIDDLE;
        # 0x06代表RC__WRITE_RESPONSE_FIRST;
        # 0x07代表RC_WRITE_RESPONSE_MIDDLE;
        s_group("Opcode", ["\x04", "\x0c", "\x0d", "\x0e", "\x06" "\x07" ])
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='MigReq', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='Partition Key', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved1', fuzzable=True)
        s_bytes(value=bytes([0x00,0x11,0xff]), size=3, max_len=3, name='Destination Queue Pair', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Acknowledge Request', fuzzable=False)
        s_bytes(value=bytes([0xf9,0xb7,0x35]), size=3, max_len=3, name='Packet Sequence Number', fuzzable=False)
    with s_block("Data"):
        s_bytes(value=bytes([0x36,0x2e,0x31,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=16, max_len=16, name='Data', fuzzable=True)
        s_bytes(value=bytes([0x86,0x60,0x36,0xf7]), size=4, max_len=4, name='Invariant CRC', fuzzable=True)

    session.connect(s_get('Send_Only_QP_InfiniBand'))


if __name__ == "__main__":
    fuzzing_main()
