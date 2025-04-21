
host_ip = ''
host_port = 5353
src_ip = ''

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_MDNS_Answers(session=session)
    fuzzing_MDNS_Queries(session=session)
    fuzzing_MDNS_Queries_Authoritative_nameservers(session=session)
    fuzzing_MDNS_Queries_Answers(session=session)
    session.fuzz()

def fuzzing_MDNS_Answers(session):
    s_initialize(name="MDNS_Answers")
    with s_block("MDNS"):
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Transaction ID", fuzzable=True)
        s_bytes(value=bytes([0x84, 0x00]), size=2, max_len=2, name="Flags", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Questions", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Answer RRs", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Authority RRs", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Additional RRs", fuzzable=True)
        with s_block("Answers"):
            s_bytes(value=bytes([0x02, 0x6d, 0x31, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00]), size=10, max_len=10,
                    name="Name", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Type", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Class", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0xf0]), size=4, max_len=4, name="Time to live")
            s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name="data length", fuzzable=True)
            s_bytes(value=bytes(src_ip), size=4, max_len=4, name="Address", fuzzable=True)
        session.connect(s_get('MDNS_Answers'))

def fuzzing_MDNS_Queries(session):
    s_initialize(name="MDNS_Queries")
    with s_block("MDNS"):
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Transaction ID", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Flags", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Questions", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Answer RRs", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Authority RRs", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Additional RRs", fuzzable=True)
        with s_block("Queries"):
            s_bytes(value=bytes([0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x05, 0x5f, 0x6d, 0x64,
                                 0x6e, 0x73, 0x04, 0x5f, 0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00]),
                    size=28, max_len=28, name="Name", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x0c]), size=2, max_len=2, name="Type", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Class", fuzzable=True)
    session.connect(s_get('MDNS_Queries'))

def fuzzing_MDNS_Queries_Authoritative_nameservers(session):
    s_initialize(name="MDNS_Queries_Authoritative_nameservers")
    with s_block("MDNS"):
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Transaction ID", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Flags", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Questions", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Answer RRs", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Authority RRs", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Additional RRs", fuzzable=True)
        with s_block("Queries"):
            s_bytes(value=bytes([0x02, 0x6d, 0x31, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00]), size=10, max_len=10,
                    name="Name", fuzzable=True)
            s_bytes(value=bytes([0x00, 0xff]), size=2, max_len=2, name="Type 1", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Class 1", fuzzable=True)
        with s_block("Authoritative nameservers"):
            s_bytes(value=bytes([0xc0, 0x0c]), size=2, max_len=2, name="Name", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Type 2", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Class 2", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0xf0]), size=4, max_len=4, name="Time to live")
            s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name="data length", fuzzable=True)
            s_bytes(value=bytes(src_ip), size=4, max_len=4, name="Address", fuzzable=True)
        session.connect(s_get('MDNS_Queries_Authoritative_nameservers'))

def fuzzing_MDNS_Queries_Answers(session):
    s_initialize(name="MDNS_Queries_Answers")
    with s_block("MDNS"):
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Transaction ID", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Flags", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Questions", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Answer RRs", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Authority RRs", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Additional RRs", fuzzable=True)
        with s_block("Queries"):
            s_bytes(value=bytes([0x05, 0x5f, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f,
                                 0x63, 0x61, 0x6c, 0x00]), size=18, max_len=18, name="Name", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x0c]), size=2, max_len=2, name="Type 1", fuzzable=True)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Class 1", fuzzable=True)
        with s_block("Authoritative nameservers"):
            s_bytes(value=bytes([0xc0, 0x0c]), size=2, max_len=2, name="Name", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0c]), size=2, max_len=2, name="Type 2", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Class 2", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x1c, 0x1f]), size=4, max_len=4, name="Time to live")
            s_bytes(value=bytes([0x00, 0x15]), size=2, max_len=2, name="data length", fuzzable=False)
            s_bytes(value=bytes([0x12, 0x4d, 0x79, 0x20, 0x46, 0x61, 0x6b, 0x65, 0x20, 0x57, 0x65, 0x62, 0x20, 0x53,
                                 0x65, 0x72, 0x76, 0x65, 0x72, 0xc0, 0x0c]), size=21, max_len=21,
                    name="Domain Name", fuzzable=False)
        session.connect(s_get('MDNS_Queries_Answers'))






if __name__ == "__main__":
    fuzzing_main()
