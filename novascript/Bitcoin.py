host_ip = ''
host_port = 8333

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="version")
    with s_block("version"):
        s_bytes(value=bytes([0xf9,0xbe,0xb4,0xd9]), size=4, max_len=4, name='bitcoin.magic', fuzzable=False)
        s_bytes(value=bytes([0x76,0x65,0x72,0x73,0x69,0x6f,0x6e,0x00,0x00,0x00,0x00,0x00]), size=12, max_len=12, name='bitcoin.command', fuzzable=False)
        s_bytes(value=bytes([0x64, 0x00,0x00,0x00]), size=4, max_len=4, name='bitcoin.length', fuzzable=False)
        s_bytes(value=bytes([0x9e,0x78,0xd1,0xbd]), size=4, max_len=4, name='bitcoin.checksum', fuzzable=False)
        s_bytes(value=bytes([0x71,0x11,0x01,0x00]), size=4, max_len=4, name='bitcoin.version.version', fuzzable=False)
        s_bytes(value=bytes([0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=8, max_len=8, name='bitcoin.version.services', fuzzable=False)
        s_bytes(value=bytes([0x1a,0x8b,0xd0,0x51,0x00,0x00,0x00,0x00]), size=8, max_len=8, name='bitcoin.version.timestamp', fuzzable=False)
        s_bytes(value=bytes([0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=8, max_len=8, name='receiving.node.address.services', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xb0,0x09,0x27,0xa5]), size=16, max_len=16, name='receiving.node.address.address', fuzzable=True)
        s_bytes(value=bytes([0x20, 0x8d]), size=2, max_len=2, name='bitcoin.address.port', fuzzable=False)
        s_bytes(value=bytes([0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00]), size=8, max_len=8, name='emmitting.node.address.services', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xb2,0x53,0x09,0xd1]), size=16, max_len=16, name='emmitting.node.address.address', fuzzable=True)
        s_bytes(value=bytes([0x20, 0x8d]), size=2, max_len=2, name='emmitting.address.port', fuzzable=False)
        s_bytes(value=bytes([0xaa,0x88,0x89,0x69,0xaf,0xb8,0x1f,0x62]), size=8, max_len=8, name='Random.nonce', fuzzable=False)
        s_bytes(value=bytes([0x0f]), size=1, max_len=1, name='Count', fuzzable=False)
        s_bytes(value=bytes([0x2f, 0x53,0x61,0x74,0x6f,0x73,0x68,0x69,0x3a,0x30,0x2e,0x38,0x2e,0x33,0x2f]), size=15, max_len=15, name='String.value', fuzzable=False)
        s_bytes(value=bytes([0x01,0x00,0x00,0x00]), size=4, max_len=4, name='Blocak.start.height', fuzzable=False)
    s_initialize(name="verack")
    with s_block("verack"):
        s_bytes(value=bytes([0xf9, 0xbe, 0xb4, 0xd9]), size=4, max_len=4, name='bitcoin.magic', fuzzable=False)
        s_bytes(value=bytes([0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=12,
                    max_len=12, name='bitcoin.command', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='bitcoin.length', fuzzable=False)
        s_bytes(value=bytes([0x5d, 0xf6, 0xe0, 0xe2]), size=4, max_len=4, name='bitcoin.checksum', fuzzable=False)
    s_initialize(name="getaddr")
    with s_block("getaddr"):
        s_bytes(value=bytes([0xf9, 0xbe, 0xb4, 0xd9]), size=4, max_len=4, name='bitcoin.magic', fuzzable=False)
        s_bytes(value=bytes([0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00]), size=12,
                    max_len=12, name='bitcoin.command', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='bitcoin.length', fuzzable=False)
        s_bytes(value=bytes([0x5d, 0xf6, 0xe0, 0xe2]), size=4, max_len=4, name='bitcoin.checksum', fuzzable=False)
    s_initialize(name="getblocks")
    with s_block("getblocks"):
        s_bytes(value=bytes([0xf9, 0xbe, 0xb4, 0xd9]), size=4, max_len=4, name='bitcoin.magic', fuzzable=False)
        s_bytes(value=bytes([0x67, 0x65, 0x74, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x00, 0x00, 0x00]), size=12,
                    max_len=12, name='bitcoin.command', fuzzable=False)
        s_bytes(value=bytes([0x65, 0x00, 0x00, 0x00]), size=4, max_len=4, name='bitcoin.length', fuzzable=False)
        s_bytes(value=bytes([0xb3, 0xb7, 0xad, 0x6e]), size=4, max_len=4, name='bitcoin.checksum', fuzzable=False)
        s_bytes(value=bytes([0x71, 0x11, 0x01, 0x00]), size=4, max_len=4, name='Protocol_version', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Count', fuzzable=False)
        s_string(value="Starting hash: 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000", name="starting.hash", fuzzable=True)
        s_string(value="Starting hash: 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",name="starting2.hash", fuzzable=False)
        s_string(value="Stopping hash: 0000000000000000000000000000000000000000000000000000000000000000",name="stoping.hash", fuzzable=False)
        session.connect(s_get('version'))
        session.connect(s_get("version"), s_get("verack"))
        session.connect(s_get("verack"), s_get("getaddr"))
        session.connect(s_get("getaddr"), s_get("getblocks"))
if __name__ == "__main__":
            fuzzing_main()