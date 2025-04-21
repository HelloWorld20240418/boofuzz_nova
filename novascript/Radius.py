
host_ip = ''
host_port = 1812


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_Radius(session=session)
    session.fuzz()


def fuzzing_Radius(session):
    s_initialize(name="Access-Request")
    with s_block("RADIUS Protocol"):
         s_bytes(value=bytes([0x01]), size=1, max_len=1, name="Code", fuzzable=False)
         s_bytes(value=bytes([0x67]), size=1, max_len=1, name="Packet identifier", fuzzable=False)
         s_bytes(value=bytes([0x00, 0x57]), size=2, max_len=2, name="Length", fuzzable=False)
         s_bytes(value=bytes([0x40, 0xb6, 0x64, 0xdb, 0xf5, 0xd6, 0x81, 0xb2, 0xad, 0xbd, 0x17, 0x69, 0x51, 0x51, 0x18, 0xc8]), size=16, max_len=16, name="Authenticator", fuzzable=True)
         with s_block("Attribute Value Pairs"):
             with s_block("User-name"):
                 s_bytes(value=bytes([0x01]), size=1, max_len=1, name="Type", fuzzable=False)
                 s_bytes(value=bytes([0x07]), size=1, max_len=1, name="Length", fuzzable=False)
                 s_string(value="steve", size=5, max_len=5, name="User-name", fuzzable=False)
             with s_block("User-password"):
                 s_bytes(value=bytes([0x02]), size=1, max_len=1, name="Type", fuzzable=False)
                 s_bytes(value=bytes([0x12]), size=1, max_len=1, name="Length", fuzzable=False)
                 s_bytes(value=bytes([0xdb, 0xc6, 0xc4, 0xb7, 0x58, 0xbe, 0x14, 0xf0, 0x05, 0xb3, 0x87, 0x7c, 0x9e, 0x2f, 0xb6, 0x01]), size=16, max_len=16, name="User-password", fuzzable=True)
             with s_block("NAS-IP-Address"):
                 s_bytes(value=bytes([0x04]), size=1, max_len=1, name="Type", fuzzable=False)
                 s_bytes(value=bytes([0x06]), size=1, max_len=1, name="Length", fuzzable=False)
                 s_bytes(value=bytes([0xc0, 0xa8, 0x00, 0x1c]), size=4, max_len=4, name="NAS-IP-Address", fuzzable=False)
             with s_block("NAS-Port"):
                 s_bytes(value=bytes([0x05]), size=1, max_len=1, name="Type", fuzzable=False)
                 s_bytes(value=bytes([0x06]), size=1, max_len=1, name="Length", fuzzable=False)
                 s_bytes(value=bytes([0x00, 0x00, 0x00, 0x7b]), size=4, max_len=4, name="NAS-Port", fuzzable=False)
             with s_block("Message-Authenticator"):
                 s_bytes(value=bytes([0x80]), size=1, max_len=1, name="Type", fuzzable=False)
                 s_bytes(value=bytes([0x12]), size=1, max_len=1, name="Length", fuzzable=False)
                 s_bytes(value=bytes([0x5f, 0x0f, 0x86, 0x47, 0xe8, 0xc8, 0x9b, 0xd8, 0x81, 0x36, 0x42, 0x68, 0xfc, 0xd0, 0x45, 0x32]), size=16, max_len=16, name="Message-Authenticator", fuzzable=True)
             with s_block("EAP-Message"):
                 s_bytes(value=bytes([0x4f]), size=1, max_len=1, name="Type", fuzzable=False)
                 s_bytes(value=bytes([0x0c]), size=1, max_len=1, name="Length", fuzzable=False)
                 with s_block("Extensible Authentication Protocol"):
                     s_bytes(value=bytes([0x02]), size=1, max_len=1, name="Code", fuzzable=False)
                     s_bytes(value=bytes([0x66]), size=1, max_len=1, name="Id", fuzzable=False)
                     s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Length", fuzzable=False)
                     s_bytes(value=bytes([0x01]), size=1, max_len=1, name="Type", fuzzable=False)
                     s_string(value="steve", size=5, max_len=5, name="Identity", fuzzable=True)


    session.connect(s_get('Access-Request'))



if __name__ == "__main__":
    fuzzing_main()
