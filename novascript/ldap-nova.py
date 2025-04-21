host_ip = ''
host_port = 389

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)

    fuzzing_bindRequest(session=session)

    session.fuzz()


def fuzzing_bindRequest(session):
    s_initialize(name="Request")
    with s_block("LDAPMessage-bindRequest"):
        s_bytes(value=bytes([0x30,0x0c,0x02,0x01]), size=4, max_len=4, name='header', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='messagerID', fuzzable=False)
        s_bytes(value=bytes([0x60,0x07]), size=2, max_len=2, name='ldap.protocolOp', fuzzable=False)
        s_bytes(value=bytes([0x02,0x01]), size=2, max_len=2, name='ldap.bindRequest_element', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='version', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x00, 0x80, 0x00]), size=4, max_len=4, name='ldap.authentication', fuzzable=True)
        session.connect(s_get("Request"))
    s_initialize(name="searchRequest")
    with s_block("searchRequest"):
        s_bytes(value=bytes([0x30, 0x53, 0x02, 0x01]), size=4, max_len=4, name='header2', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='messagerID2', fuzzable=False)
        s_bytes(value=bytes([0x63, 0x4e]), size=2, max_len=2, name='ldap.protocolOp2', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x00, 0x0a, 0x01]), size=4, max_len=4, name='ldap.baseObject', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='ldap.scope', fuzzable=False)
        s_bytes(value=bytes([0x0a, 0x01,0x00]), size=3, max_len=3, name='ldap.derefAliases', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x00]), size=3, max_len=3, name='ldap.sizeLimit', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x00]), size=3, max_len=3, name='ldap.timeLimit', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x01, 0x00]), size=3, max_len=3, name='ldap.typesOnly', fuzzable=False)
        s_bytes(value=bytes([0xa9, 0x39]), size=2, max_len=2, name=' ldap.filter', fuzzable=False)
        s_bytes(value=bytes([0x81, 0x1c]), size=2, max_len=2, name='ldap.extensibleMatch_element', fuzzable=False)
        s_bytes(value=bytes(
            {0x32, 0x2e, 0x31, 0x36, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31,
             0x2e, 0x31,0x31, 0x33, 0x37, 0x33, 0x30, 0x2e, 0x33,0x2e,
             0x33,0x2e,0x32,0x2e,0x34,0x36,0x2e,0x31}), size=28, max_len=28, name='ldap.matchingRule', fuzzable=True)
        s_bytes(value=bytes([0x82, 0x10,0x64,0x65,0x70,0x61,0x72,0x74,0x6d,
                             0x65,0x6e,0x74,0x4e,0x75,0x6d,0x62,0x65,0x72]), size=18, max_len=18, name='ldap.type', fuzzable=True)
        s_bytes(value=bytes([0x83,0x07,0x3e,0x3d,0x4e,0x34,0x37,0x30,0x39]), size=9, max_len=9, name='ldap.matchValue', fuzzable=True)
        s_bytes(value=bytes([0x30, 0x00]), size=2, max_len=2, name='ldap.attributes', fuzzable=True)

        session.connect(s_get("Request"), s_get("searchRequest"))











if __name__ == "__main__":
    fuzzing_main()