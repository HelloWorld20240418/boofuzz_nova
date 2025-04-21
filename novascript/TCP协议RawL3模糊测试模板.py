interface_port = ''
src_ip = []
dst_ip = []


def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x0800)),nova_session_param=nova_session_param )
    fuzzing_define_proto(session=session)
    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="IPv4")
    with s_block("IPv4"):
        s_random(value=bytes([0x45]), num_mutations=25,min_length=1,max_length=1,name='Version', fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1,max_length=1,num_mutations=25, name='DSF', fuzzable=False)
        s_random(value=bytes([0x00, 0x2c]), min_length=2,max_length=2,num_mutations=25, name='Total Length', fuzzable=False)
        s_random(value=bytes([0x5b, 0x4d]), min_length=2,max_length=2,num_mutations=25,  name='Identification', fuzzable=False)
        s_random(value=bytes([0x00, 0x00]), min_length=2,max_length=2,num_mutations=25,  name='Flags', fuzzable=False)
        s_random(value=bytes([0xff]), min_length=1,max_length=1,num_mutations=25,name='Time to Live', fuzzable=False)
        s_random(value=bytes([0x06]),min_length=1,max_length=1,num_mutations=25,name='Protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_random(value=bytes(src_ip), min_length=4,max_length=4,num_mutations=25, name='Source Address', fuzzable=False)
        s_random(value=bytes(dst_ip), min_length=4,max_length=4,num_mutations=25,name='Destination Address', fuzzable=False)
    with s_block("TCP"):
        s_random(value=bytes([0x4f,0xf0]),min_length=2,max_length=2,num_mutations=25, name="source port",fuzzable=True)
        s_random(value=bytes([0x00,0x50]),min_length=2,max_length=2,num_mutations=25,   name="Destination port",fuzzable=False)
        s_random(value=bytes([0x96, 0x3c,0xc8,0xab]), min_length=4,max_length=4,num_mutations=25, name="sequence number",
                 fuzzable=False)
        s_random(value=bytes([0x00, 0x00, 0x00, 0x00]),min_length=4,max_length=4,num_mutations=25,
                 name="Acknowledgment number",fuzzable=True)
        s_random(value=bytes([0x60, 0x02]),min_length=2,max_length=2,num_mutations=25, name='Flags2', fuzzable=False)
        s_random(value=bytes([0xea, 0x60]), min_length=2,max_length=2,num_mutations=25, name='window', fuzzable=True)
        #s_checksum("TCP", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_checksum(block_name='TCP', algorithm='udp', name='Checksum',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        s_random(value=bytes([0x00, 0x00]), min_length=2,max_length=2,num_mutations=25, name='urgent pointer', fuzzable=False)
        s_random(value=bytes([0x02, 0x04, 0x05, 0xb4]),min_length=4,max_length=4,num_mutations=25,name="option",fuzzable=True)
        #s_random(value=bytes([0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00]),min_length=24,max_length=24,num_mutations=25, name='data', fuzzable=True)

    session.connect(s_get('IPv4'))


if __name__ == "__main__":
    fuzzing_main()