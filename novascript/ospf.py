interface_port = ''
src_ip = []
dst_ip = []


def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x0800)), nova_session_param=nova_session_param)
    fuzzing_ospf_hello_packet(session=session)
    fuzzing_ospf_db_description(session=session)
    fuzzing_ospf_ls_request(session=session)
    fuzzing_ospf_ls_update(session=session)
    fuzzing_ospf_ls_acknowledge(session=session)
    session.fuzz()


def fuzzing_ospf_hello_packet(session):
    # ---------- OSPF Hello Packet ---------- #

    s_initialize(name="OSPF Hello Packet")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0xc0]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x44]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x2c]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_random(value=bytes([0x01]), min_length=1, max_length=1, name='Time to Live', fuzzable=True)
        s_bytes(value=bytes([0x59]), size=1, max_len=1, name='proto', fuzzable=False)
        s_bytes(value=bytes([0x6c, 0xbc]), size=2, max_len=2, name='Header Checksum', fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes([0xe0, 0x00, 0x00, 0x05]), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("OSPF"):
        with s_block("OSPF Header"):
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Version', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Message Type', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x30]), size=2, max_len=2, name='Packet Length', fuzzable=False)
            s_bytes(value=bytes([0x03, 0x03, 0x03, 0x03]), size=4, max_len=4, name='Source OSPF Router', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Area ID', fuzzable=False)
            s_bytes(value=bytes([0xc2, 0x89]), size=2, max_len=2, name='Checksum', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Auth Type')
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Auth Data')
        with s_block("OSPF Hello Packet"):
            s_bytes(value=bytes([0xff, 0xff, 0xff, 0x00]), size=4, max_len=4, name='Network Mask', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name='Hello Interval', fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Options', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Router Priority', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x28]), size=4, max_len=4, name='Router Dead Interval',
                    fuzzable=True)
            s_bytes(value=bytes([0x17, 0x01, 0x01, 0x02]), size=4, max_len=4, name='Designated Router',
                    fuzzable=True)
            s_bytes(value=bytes([0x17, 0x01, 0x01, 0x03]), size=4, max_len=4, name='Backup Designated Router',
                    fuzzable=True)
            s_bytes(value=bytes([0x02, 0x02, 0x02, 0x02]), size=4, max_len=4, name='Active Neighbor',
                    fuzzable=True)
    session.connect(s_get('OSPF Hello Packet'))



def fuzzing_ospf_db_description(session):
    # ---------- OSPF DB Description ---------- #
  
    s_initialize(name="OSPF DB Description")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0xc0]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x34]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x23]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_random(value=bytes([0x01]), min_length=1, max_length=1, name='Time to Live', fuzzable=True)
        s_bytes(value=bytes([0x59]), size=1, max_len=1, name='proto', fuzzable=False)
        s_bytes(value=bytes([0x84, 0x88]), size=2, max_len=2, name='Header Checksum', fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("OSPF"):
        with s_block("OSPF Header"):
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Version', fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Message Type', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x20]), size=2, max_len=2, name='Packet Length', fuzzable=False)
            s_bytes(value=bytes([0x02, 0x02, 0x02, 0x02]), size=4, max_len=4, name='Source OSPF Router', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Area ID', fuzzable=False)
            s_bytes(value=bytes([0xdd, 0xd6]), size=2, max_len=2, name='Checksum', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Auth Type')
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Auth Data')
        with s_block("OSPF DB Description"):
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Interface MTU', fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Options', fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name='DB Description', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x19, 0xfc]), size=4, max_len=4, name='Active Neighbor',
                    fuzzable=False)
    session.connect(s_get('OSPF DB Description'))



def fuzzing_ospf_ls_request(session):
    # ---------- OSPF LS Request ---------- #
   
    s_initialize(name="OSPF LS Request")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0xc0]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x38]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x43]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_random(value=bytes([0x01]), min_length=1, max_length=1, name='Time to Live', fuzzable=True)
        s_bytes(value=bytes([0x59]), size=1, max_len=1, name='proto', fuzzable=False)
        s_bytes(value=bytes([0x84, 0x64]), size=2, max_len=2, name='Header Checksum', fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("OSPF"):
        with s_block("OSPF Header"):
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Version', fuzzable=False)
            s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Message Type', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x24]), size=2, max_len=2, name='Packet Length', fuzzable=False)
            s_bytes(value=bytes([0x03, 0x03, 0x03, 0x03]), size=4, max_len=4, name='Source OSPF Router', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Area ID', fuzzable=False)
            s_bytes(value=bytes([0xe6, 0xca]), size=2, max_len=2, name='Checksum', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Auth Type')
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Auth Data')
        with s_block("OSPF LS Request"):
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x03]), size=4, max_len=4, name='LS Type',
                    fuzzable=False)
            s_bytes(value=bytes([0x0c, 0x01, 0x01, 0x00]), size=4, max_len=4, name='Link State ID',
                    fuzzable=False)
            s_bytes(value=bytes([0x02, 0x02, 0x02, 0x02]), size=4, max_len=4, name='Advertising Router',
                    fuzzable=False)
    session.connect(s_get('OSPF LS Request'))



def fuzzing_ospf_ls_update(session):
    # ---------- OSPF LS Update ---------- #
    
    s_initialize(name="OSPF LS Update")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0xc0]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x4c]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x25]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_random(value=bytes([0x01]), min_length=1, max_length=1, name='Time to Live', fuzzable=True)
        s_bytes(value=bytes([0x59]), size=1, max_len=1, name='proto', fuzzable=False)
        s_bytes(value=bytes([0x84, 0x6e]), size=2, max_len=2, name='Header Checksum', fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("OSPF"):
        with s_block("OSPF Header"):
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Version', fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Message Type', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x38]), size=2, max_len=2, name='Packet Length', fuzzable=False)
            s_bytes(value=bytes([0x02, 0x02, 0x02, 0x02]), size=4, max_len=4, name='Source OSPF Router', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Area ID', fuzzable=False)
            s_bytes(value=bytes([0x09, 0xac]), size=2, max_len=2, name='Checksum 1', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Auth Type')
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Auth Data')
        with s_block("OSPF LS Update"):
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x01]), size=4, max_len=4, name='LS Type',
                    fuzzable=False)
            with s_block("LSA-type"):
                s_bytes(value=bytes([0x00, 0x03]), size=2, max_len=2, name='LS Age', fuzzable=False)
                s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Options', fuzzable=False)
                s_bytes(value=bytes([0x03]), size=1, max_len=1, name='LS Type', fuzzable=False)
                s_bytes(value=bytes([0x0c, 0x01, 0x01, 0x00]), size=4, max_len=4, name='Link State ID',
                        fuzzable=False)
                s_bytes(value=bytes([0x02, 0x02, 0x02, 0x02]), size=4, max_len=4, name='Advertising Router',
                        fuzzable=False)
                s_bytes(value=bytes([0x80, 0x00, 0x00, 0x01]), size=4, max_len=4, name='Sequence Number',
                        fuzzable=False)
                s_bytes(value=bytes([0x5d, 0xb9]), size=2, max_len=2, name='Checksum 2', fuzzable=False)
                s_bytes(value=bytes([0x00, 0x1c]), size=2, max_len=2, name='Length', fuzzable=False)
                s_bytes(value=bytes([0xff, 0xff, 0xff, 0x00]), size=4, max_len=4, name='Netmask',
                        fuzzable=False)
                s_bytes(value=bytes([0x00]), size=1, max_len=1, name='TOS', fuzzable=False)
                s_bytes(value=bytes([0x00, 0x00, 0x30]), size=3, max_len=3, name='Metric', fuzzable=False)
    session.connect(s_get('OSPF LS Update'))



def fuzzing_ospf_ls_acknowledge(session):
    # ---------- OSPF LS Acknowledge ---------- #
    
    s_initialize(name="OSPF LS Acknowledge")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0xc0]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x54]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x34]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_random(value=bytes([0x01]), min_length=1, max_length=1, name='Time to Live', fuzzable=True)
        s_bytes(value=bytes([0x59]), size=1, max_len=1, name='proto', fuzzable=False)
        s_bytes(value=bytes([0xbc, 0x55]), size=2, max_len=2, name='Header Checksum', fuzzable=False)
        s_bytes(value=bytes([0xc0, 0xa8, 0x10, 0x1b]), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes([0xe0, 0x00, 0x00, 0x05]), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("OSPF"):
        with s_block("OSPF Header"):
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Version', fuzzable=False)
            s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Message Type', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x40]), size=2, max_len=2, name='Packet Length', fuzzable=False)
            s_bytes(value=bytes([0x02, 0x02, 0x02, 0x02]), size=4, max_len=4, name='Source OSPF Router', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Area ID', fuzzable=False)
            s_bytes(value=bytes([0xee, 0x21]), size=2, max_len=2, name='Checksum 1', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Auth Type')
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Auth Data')
        with s_block("LSA-type 1"):
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='LS Age', fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Options', fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name='LS Type', fuzzable=False)
            s_bytes(value=bytes([0x03, 0x03, 0x03, 0x03]), size=4, max_len=4, name='Link State ID',
                    fuzzable=False)
            s_bytes(value=bytes([0x03, 0x03, 0x03, 0x03]), size=4, max_len=4, name='Advertising Router',
                    fuzzable=False)
            s_bytes(value=bytes([0x80, 0x00, 0x00, 0x0c]), size=4, max_len=4, name='Sequence Number',
                    fuzzable=False)
            s_bytes(value=bytes([0x4e, 0x8c]), size=2, max_len=2, name='Checksum 2', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x30]), size=2, max_len=2, name='Length', fuzzable=False)
        with s_block("LSA-type 2"):
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='LS Age', fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Options', fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name='LS Type', fuzzable=False)
            s_bytes(value=bytes([0x17, 0x01, 0x01, 0x03]), size=4, max_len=4, name='Link State ID',
                    fuzzable=False)
            s_bytes(value=bytes([0x03, 0x03, 0x03, 0x03]), size=4, max_len=4, name='Advertising Router',
                    fuzzable=False)
            s_bytes(value=bytes([0x80, 0x00, 0x00, 0x02]), size=4, max_len=4, name='Sequence Number',
                    fuzzable=False)
            s_bytes(value=bytes([0x8e, 0x8e]), size=2, max_len=2, name='Checksum 2', fuzzable=False)
            s_bytes(value=bytes([0x00, 0x20]), size=2, max_len=2, name='Length', fuzzable=False)
    session.connect(s_get('OSPF LS Acknowledge'))



if __name__ == "__main__":
    fuzzing_main()
