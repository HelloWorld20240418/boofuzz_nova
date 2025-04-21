
src_ip = []
dst_ip = []
host_ip = ''
host_port = 4789

def main():

    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_vxlan(session=session)
    session.fuzz()

#基于vxlan的icmp请求
def fuzzing_vxlan(session):
    s_initialize("VXLAN")
    with s_block("Virtual eXtensible Local Area Network"):
        s_bytes(value=bytes([0x08,0x00]), size=2, max_len=2, name="Flags", fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name="Group Policy ID", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x1f, 0x40]), size=3, max_len=3, name="VXLAN Network Identifier (VNI)", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Reserved", fuzzable=False)
        s_bytes(value=bytes([0x54, 0x89, 0x98, 0x16, 0x2e, 0x86]), size=6, max_len=6, name="Destination", fuzzable=False)
        s_bytes(value=bytes([0x54, 0x89, 0x98, 0x6c, 0x14, 0xe5]), size=6, max_len=6, name="Source", fuzzable=False)
        s_bytes(value=bytes([0x08, 0x00]), size=2, max_len=2, name="Type", fuzzable=False)

    with s_block("Internet Protocol Version 4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1,name='Version_Header Length', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Differentiated Services Field',fuzzable=False)
        s_bytes(value=bytes([0x00, 0x3c]), size=2, max_len=2, name='Total Length',fuzzable=False)
        s_bytes(value=bytes([0xde, 0x38]), size=2, max_len=2, name='Identification',fuzzable=False)
        s_bytes(value=bytes([0x40, 0x00]), size=2, max_len=2, name='Fragment Offset',fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Time to Live',fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1,name='Protocol', fuzzable=False)
        s_checksum("Internet Protocol Version 4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes(src_ip), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(dst_ip), size=14, max_len=4, name='Destination Address', fuzzable=False)

    with s_block("Internet Control Message Protocol"):
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Type',fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Code',fuzzable=False)
        s_checksum("Internet Control Message Protocol", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes([0x38, 0xde]), size=2, max_len=2,name='Identifier', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2,name='Sequence Number', fuzzable=True)
        s_bytes(value=bytes([0xac, 0x10, 0x01, 0x0a, 0xac, 0x10, 0x01, 0x0a, 0xac, 0x10, 0x01, 0x0a, 0xac, 0x10, 0x01, 0x0a, 0xac, 0x10, 0x01, 0x0a, 0xac, 0x10, 0x01, 0x0a, 0xac, 0x10, 0x01, 0x0a, 0xac, 0x10, 0x01, 0x0a, ]), size=32, max_len=32,name='Data', fuzzable=True)


    session.connect(s_get("VXLAN"))


if __name__ == "__main__":
    main()
