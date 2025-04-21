
host_ip = ''
host_port = 4791

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    CM_UD(session)
    session.fuzz()


def CM_UD(session):
    s_initialize(name="ConnectRequest")
    with s_block("Base_Transport_Header"):
        s_bytes(value=bytes([0x64]), size=1, max_len=1, name='Opcode1', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='MigReq1', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='Partition Key', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved1', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x01]), size=3, max_len=3, name='Destination Queue Pair', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Acknowledge Request', fuzzable=False)
        s_bytes(value=bytes([0x00,0x39,0x6c]), size=3, max_len=3, name='Packet Sequence Number', fuzzable=False)

    with s_block("DETH"):
        s_bytes(value=bytes([0x80,0x01,0x00,0x00]), size=4, max_len=4, name='Queue Key', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved2', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x01]), size=3, max_len=3, name='Source Queue Pair', fuzzable=True)

    with s_block("MAD_Header"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Base Version', fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='Management Class', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Class Version', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Method', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Status', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Class Specific', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x06,0x36,0xef,0x56,0x09]), name="Transaction ID", fuzzable=True)
        s_bytes(value=bytes([0x00,0x10]), size=2, max_len=2, name='Attribute ID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Reserved3', fuzzable=True)
        s_bytes(value=bytes([0x30,0x00,0x00,0x00]), size=4, max_len=4, name='Attribute Modifier', fuzzable=False)

    with s_block("CM ConnectRequest"):
        s_bytes(value=bytes([0x09,0x56,0xef,0x36]), size=4, max_len=4, name='Local Communication ID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x15,0xb3]), size=4, max_len=4, name='Reserved4', fuzzable=True)

        with s_block("IP CM ServiceID"):
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x01]), size=5, max_len=5, name='Prefix', fuzzable=False)
            s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Protocl', fuzzable=False)
            s_bytes(value=bytes([0x48,0x53]), size=2, max_len=2, name='Destination Port: 0x4853', fuzzable=False)

        s_bytes(value=bytes([0x10,0x70,0xfd,0x03,0x00,0xcb,0xdf,0xfe]), size=8, max_len=8, name='Local CA GUID', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Reserved5', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Local Q_Key', fuzzable=False)
        s_bytes(value=bytes([0x00,0x11,0xf4]), size=3, max_len=3, name='Local QPN', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Responder Resources', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00]), size=3, max_len=3, name='Local EECN', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Initiator Depth', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00]), size=3, max_len=3, name='Remote EECN', fuzzable=False)
        s_bytes(value=bytes([0xb0]), size=1, max_len=1, name='Remote CM Response Timeout', fuzzable=False)
        s_bytes(value=bytes([0x94,0xdc,0xb0]), size=3, max_len=3, name='Starting PSN', fuzzable=False)
        s_bytes(value=bytes([0xb7]), size=1, max_len=1, name='Local CM Response Timeout', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='Partition Key', fuzzable=False)
        s_bytes(value=bytes([0x37]), size=1, max_len=1, name='Path Packet Payload MTU', fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name='Max CM Retries', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='Primary Local Port LID', fuzzable=False)
        s_bytes(value=bytes([0xff, 0xff]), size=2, max_len=2, name='Primary Remote Port LID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x0a,0x00,0x00,0x02]), size=16, max_len=16, name='Primary Local Port GID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x0a,0x00,0x00,0x04]), size=16, max_len=16, name='Primary Remote Port GID', fuzzable=True)
        s_bytes(value=bytes([0x76,0x41,0xe0,0x00]), size=4, max_len=4, name='Primary Flow Label', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Primary Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='Primary Hop Limit', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Primary SL', fuzzable=False)
        s_bytes(value=bytes([0x90]), size=1, max_len=1, name='Primary Local ACK Timeout', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Alternate Local Port LID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Alternate Remote Port LID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=16, max_len=16, name='Alternate Local Port GID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=16, max_len=16, name='Alternate Remote Port GID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Alternate Flow Label', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Alternate Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Alternate Hop Limit', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Alternate SL', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Alternate Local ACK Timeout', fuzzable=False)

        with s_block("IP CM Private Data"):
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name='IP CM Major Version', fuzzable=False)
            s_bytes(value=bytes([0x40]), size=1, max_len=1, name='IP CM IP Version', fuzzable=False)
            s_bytes(value=bytes([0xbe,0xd5]), size=2, max_len=2, name='IP CM Source Port', fuzzable=False)
            s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0x00,0x02]), size=16, max_len=16, name='IP CM Source IP', fuzzable=False)
            s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0x00,0x04]), size=16, max_len=16, name='IP CM Destination IP', fuzzable=False)
            s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=56, max_len=56, name='IP CM Consumer PrivateData', fuzzable=False)
            s_bytes(value=bytes([0x0c,0x42,0xc2,0x43]), size=4, max_len=4, name='Invariant CRC', fuzzable=False)

    s_initialize(name="ReadyToUse")
    with s_block("Base_Transport_Header"):
        s_bytes(value=bytes([0x64]), size=1, max_len=1, name='Opcode2', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='MigReq2', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='Partition Key', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved6', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x01]), size=3, max_len=3, name='Destination Queue Pair', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Acknowledge Request', fuzzable=False)
        s_bytes(value=bytes([0x00,0x39,0x6d]), size=3, max_len=3, name='Packet Sequence Number', fuzzable=False)

    with s_block("DETH"):
        s_bytes(value=bytes([0x80,0x01,0x00,0x00]), size=4, max_len=4, name='Queue Key', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved7', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x01]), size=3, max_len=3, name='Source Queue Pair', fuzzable=False)

    with s_block("MAD_Header"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Base Version', fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='Management Class', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Class Version', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Method', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Status', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Class Specific', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x06,0x36,0xef,0x56,0x09]), size=8,max_len=8,name="Transaction ID", fuzzable=False)
        s_bytes(value=bytes([0x00,0x14]), size=2, max_len=2, name='Attribute ID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Reserved8', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Attribute Modifier', fuzzable=False)
    with s_block("CM ReadyToUse"):
        s_bytes(value=bytes([0x09,0x56,0xef,0x36]), size=4, max_len=4, name='Local Communication ID', fuzzable=False)
        s_bytes(value=bytes([0x0b,0x48,0x5c,0x1b]), size=4, max_len=4, name='Attribute Modifier', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                             ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                             ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=224, max_len=224, name='PrivateData', fuzzable=False)
        s_bytes(value=bytes([0xbc,0x13,0xf2,0xdc]), size=4, max_len=4, name='Invariant CRC', fuzzable=False)

    s_initialize(name="RC_SEND_ONLY")
    with s_block("Base_Transport_Header"):
            # 0x04代表RC_SEND_ONLY;
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Opcode3', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='MigReq3', fuzzable=False)
        s_bytes(value=bytes([0xff, 0xff]), size=2, max_len=2, name='Partition Key', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved9', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x11, 0xff]), size=3, max_len=3, name='Destination Queue Pair', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Acknowledge Request', fuzzable=False)
        s_bytes(value=bytes([0xf9, 0xb7, 0x35]), size=3, max_len=3, name='Packet Sequence Number', fuzzable=False)
    with s_block("Data"):
        s_bytes(value=bytes(
            [0x36, 0x2e, 0x31, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                size=16, max_len=16, name='Data', fuzzable=False)
        s_bytes(value=bytes([0x86, 0x60, 0x36, 0xf7]), size=4, max_len=4, name='Invariant CRC', fuzzable=False)

    s_initialize(name="UD_SEND_ONLY")
    with s_block("Base_Transport_Header"):
        # 0x64代表UD_SEND_ONLY;
        s_bytes(value=bytes([0x64]), size=1, max_len=1, name='Opcode4', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='MigReq4', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='Partition Key', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved10', fuzzable=True)
        s_bytes(value=bytes([0x00,0x11,0xff]), size=3, max_len=3, name='Destination Queue Pair', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Acknowledge Request', fuzzable=False)
        s_bytes(value=bytes([0xf9,0xb7,0x35]), size=3, max_len=3, name='Packet Sequence Number', fuzzable=False)

    with s_block("DETH - Datagram Extended Transport Header"):
        s_bytes(value=bytes([0x01, 0x23, 0x45, 0x67]), size=4, max_len=4, name="Queue Key_54", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Reserved_58", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x11, 0xfc]), size=3, max_len=3, name="Source Queue Pair_59", fuzzable=False)

    with s_block("Data"):
        s_bytes(value=bytes([0x36,0x2e,0x31,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=16, max_len=16, name='Data', fuzzable=False)
        s_bytes(value=bytes([0x86,0x60,0x36,0xf7]), size=4, max_len=4, name='Invariant CRC', fuzzable=False)

    s_initialize(name="DisconnectRequest")
    with s_block("Base_Transport_Header"):
        s_bytes(value=bytes([0x64]), size=1, max_len=1, name='Opcode5', fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='MigReq5', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff]), size=2, max_len=2, name='Partition Key', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved11', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x01]), size=3, max_len=3, name='Destination Queue Pair', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Acknowledge Request', fuzzable=False)
        s_bytes(value=bytes([0x00,0x39,0x70]), size=3, max_len=3, name='Packet Sequence Number', fuzzable=False)

    with s_block("DETH"):
        s_bytes(value=bytes([0x80,0x01,0x00,0x00]), size=4, max_len=4, name='Queue Key', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved2', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x01]), size=3, max_len=3, name='Source Queue Pair', fuzzable=False)

    with s_block("MAD_Header"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Base Version', fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='Management Class', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Class Version', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Method', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Status', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Class Specific', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x06,0x36,0xef,0x56,0x0a]), name="Transaction ID", fuzzable=False)
        s_bytes(value=bytes([0x00,0x15]), size=2, max_len=2, name='Attribute ID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Reserved12', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Attribute Modifier', fuzzable=False)

    with s_block("CM ConnectRequest"):
        s_bytes(value=bytes([0x0a,0x56,0xef,0x36]), size=4, max_len=4, name='Local Communication ID', fuzzable=False)
        s_bytes(value=bytes([0x08,0x48,0x5c,0x1b]), size=4, max_len=4, name='Remote Communication ID', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x12, 0x00]), size=3, max_len=3, name='Remote QPN/EECN', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved13', fuzzable=True)
        s_bytes(value=bytes(
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00
                , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                size=220, max_len=220, name='PrivateData', fuzzable=False)
        s_bytes(value=bytes([0xc5,0xa9,0x28,0x82]), size=4, max_len=4, name='Invariant CRC', fuzzable=False)


    session.connect(s_get('ConnectRequest'))
    session.connect(s_get('ReadyToUse'))
    session.connect(s_get('RC_SEND_ONLY'))
    session.connect(s_get('UD_SEND_ONLY'))
    session.connect(s_get('DisconnectRequest'))


if __name__ == "__main__":
    fuzzing_main()