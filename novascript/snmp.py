
host_ip = ''
host_port = 161

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_get_request(session=session)
    fuzzing_get_next_request(session=session)
    fuzzing_snmpv3_get_request(session=session)
    fuzzing_snmpv3_encryptedPDU(session=session)
    fuzzing_snmpv3_get_next_request(session=session)

    session.fuzz()

    # -----------SNMPv1&SNMPv2c------------#


def fuzzing_get_request(session):
    s_initialize(name="get_request")
    with s_block("get_request"):
        s_bytes(value=bytes([0x30, 0x26]), size=2, max_len=2, name='SNMP_header', fuzzable=False)
        s_group("Version", [bytes([0x02, 0x01, 0x00]), bytes([0x02, 0x01, 0x01])])
        s_bytes(value=bytes([0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63]), size=8, max_len=8, name='community',
                fuzzable=True)
        s_bytes(value=bytes([0xa0, 0x19]), size=2, max_len=2, name='get_request_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x00]), size=3, max_len=3, name='request_id', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01, 0x00]), size=3, max_len=3, name='error_status', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01, 0x00]), size=3, max_len=3, name='error_index', fuzzable=True)
        s_bytes(value=bytes([0x30, 0x0e]), size=2, max_len=2, name='variable_bindings_header', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00]),
                size=14, max_len=14, name='Value', fuzzable=True)
    session.connect(s_get('get_request'))

def fuzzing_get_next_request(session):
    s_initialize(name="get_next_request")
    with s_block("get_next_request"):
        s_bytes(value=bytes([0x30, 0x26]), size=2, max_len=2, name='SNMP_header', fuzzable=False)
        s_group("Version", [bytes([0x02, 0x01, 0x00]), bytes([0x02, 0x01, 0x01])])
        s_bytes(value=bytes([0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63]), size=8, max_len=8, name='community',
                fuzzable=True)
        s_bytes(value=bytes([0xa1, 0x19]), size=2, max_len=2, name='get_next_request_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x01]), size=3, max_len=3, name='request_id', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01, 0x00]), size=3, max_len=3, name='error_status', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01, 0x00]), size=3, max_len=3, name='error_index', fuzzable=True)
        s_bytes(value=bytes([0x30, 0x0e]), size=2, max_len=2, name='variable_bindings_header', fuzzable=False)
        s_bytes(value=bytes([0x30,0x0c,0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00]),
                size=14, max_len=14, name='Value', fuzzable=True)
        session.connect(s_get('get_next_request'))

    # -----------SNMPv3------------#
def fuzzing_snmpv3_get_request(session):
    s_initialize(name="snmpv3_get_request")
    with s_block("snmpv3_get_request"):
        s_bytes(value=bytes([0x30, 0x4b]), size=2, max_len=2, name='SNMP_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x03]), size=3, max_len=3, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x11]), size=2, max_len=2, name='msgGlobalData_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x04, 0x30, 0xf6, 0xf3, 0xd4]), size=6, max_len=6, name='msg_id', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x03, 0x00, 0xff, 0xe3]), size=5, max_len=5, name='msgMaxSize', fuzzable=True)
        s_bytes(value=bytes([0x04, 0x01, 0x04]), size=3, max_len=3, name='msgFlags', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01, 0x03]), size=3, max_len=3, name='msgSecurityModel', fuzzable=True)
        s_bytes(value=bytes([0x40, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00]), size=9, max_len=9,
                name='msgAuthoritativeEngineBoots', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01, 0x00]), size=3, max_len=3, name='msgAuthoritativeEngineTime', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x00]), size=2, max_len=2, name='msgUserName', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x00]), size=2, max_len=2, name='msgAuthenticationParameters', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x00]), size=2, max_len=2, name='msgPrivacyParameters', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x21, 0x04, 0x0d]), size=4, max_len=4, name='msgData_plaintext', fuzzable=False)
        s_bytes(value=bytes([0x80, 0x00, 0x1f, 0x88, 0x80, 0x59, 0xdc, 0x48, 0x61, 0x45, 0xa2, 0x63, 0x22]), size=13,
                max_len=13, name='contextEngineID', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x00]), size=4, max_len=4, name='contextName', fuzzable=False)
        s_bytes(value=bytes(
            [0xa0, 0x0e, 0x02, 0x04, 0x7d, 0x0e, 0x08, 0x2e, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00]), size=16,
                max_len=16, name='data_get-request', fuzzable=True)
        session.connect(s_get('snmpv3_get_request'))

def fuzzing_snmpv3_encryptedPDU(session):
    s_initialize(name="snmpv3_encryptedPDU")
    with s_block("snmpv3_encryptedPDU"):
        s_bytes(value=bytes([0x30, 0x81, 0xb1]), size=3, max_len=3, name='SNMP_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x03]), size=3, max_len=3, name='msgVersion', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x11]), size=2, max_len=2, name='msgGlobalDate_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x04, 0x30, 0xf6, 0xf3, 0xd5]), size=6, max_len=6, name='msgID', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x03, 0x00, 0xff, 0xe3]), size=5, max_len=5, name='msgMaxSize', fuzzable=True)
        s_bytes(value=bytes([0x04, 0x01, 0x07]), size=3, max_len=3, name='msgFlags', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01, 0x03]), size=3, max_len=3, name='msfSecurityModel', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x37, 0x30, 0x35]), size=4, max_len=4, name='msgAuthoritativeEngineID_header',
                fuzzable=False)
        s_bytes(value=bytes([0x04, 0x0d, 0x80, 0x00, 0x1f, 0x88]), size=6, max_len=6, name='Engine_Enterprise_ID',
                fuzzable=False)
        s_bytes(value=bytes([0x80]), size=3, max_len=3, name='Engine_ID_Format', fuzzable=False)
        s_bytes(value=bytes([0x59, 0xdc, 0x48, 0x61]), size=4, max_len=4, name='Engine_ID_Data', fuzzable=False)
        s_bytes(value=bytes([0x45, 0xa2, 0x63, 0x22]), size=4, max_len=4, name='Engine_ID_Date2', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x08]), size=3, max_len=3, name='msgAuthoritativeEngineBoots', fuzzable=False)
        s_bytes(value=bytes([0x02, 0X02, 0X0a, 0xb9]), size=4, max_len=4, name='msgAuthoritativeEngineTime',
                fuzzable=False)
        s_bytes(value=bytes([0x04, 0X05, 0X70, 0x59, 0x70, 0x70, 0x6f]), size=7, max_len=7, name='msgAUserName',
                fuzzable=False)
        s_bytes(value=bytes([0x04, 0X0c, 0X19, 0x39, 0x5e, 0x67, 0x89, 0x4f, 0xda, 0x18, 0x24, 0x14, 0x84, 0x9f]),
                size=14, max_len=14, name='msgAuthenticationParameters', fuzzable=False)
        s_bytes(value=bytes([0x04, 0X08, 0x00, 0x00, 0x00, 0x01, 0x03, 0xd5, 0x32, 0x1a]), size=10, max_len=10,
                name='msgPrivacyParameters', fuzzable=True)
        s_bytes(value=bytes(
            [0x04, 0x060, 0x82, 0x6e, 0xcf, 0x64, 0x43, 0x95, 0x6d, 0x4c, 0x36, 0x4b, 0xfc, 0x6f, 0x6f, 0xfc, 0x8e,
             0xe0, 0xdf, 0x00, 0x0f, 0xfd, 0x09, 0x55, 0xaf, 0x12, 0xd2, 0xc0, 0xf3, 0xc6, 0x0f, 0xad, 0xea, 0x41, 0x7d,
             0x2d, 0xb8, 0x0c, 0x0b, 0x2c, 0x1f, 0xa7, 0xa4, 0x6c, 0xe4, 0x4f, 0x9f, 0x16, 0xe1, 0x5e, 0xe8, 0x30, 0xa4,
             0x98, 0x81, 0xf6, 0x0e, 0xcf, 0xa7, 0x57, 0xd2, 0xf0, 0x40, 0x00, 0xeb, 0x39, 0xa9, 0x40, 0x58, 0x12, 0x1d,
             0x88, 0xca, 0x20, 0xee, 0xef, 0x4e, 0x6b, 0xf0, 0x67, 0x84, 0xc6, 0x7c, 0x15, 0xf1, 0x44, 0x91, 0x5d, 0x9b,
             0xc2, 0xc6, 0xa0, 0x46, 0x1d, 0xa9, 0x2a, 0x4a, 0xbe]), size=98, max_len=98, name='encryptedPDU',
                fuzzable=True)
    session.connect(s_get('snmpv3_encryptedPDU'))

def fuzzing_snmpv3_get_next_request(session):
    s_initialize(name="snmpv3_get_next_request")
    with s_block("snmpv3_get_next_request"):
        s_bytes(value=bytes([0x30, 0x81, 0xb5]), size=3, max_len=3, name='SNMP_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x03]), size=3, max_len=3, name='msgVersion', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x11]), size=2, max_len=2, name='msgGlobalDate_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x04, 0x00, 0x9e, 0x5d, 0x1b]), size=6, max_len=6, name='msgID', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x03, 0x00, 0xff, 0xe3]), size=5, max_len=5, name='msgMaxSize', fuzzable=True)
        s_bytes(value=bytes([0x04, 0x01, 0x05]), size=3, max_len=3, name='msfFlags', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01, 0x03]), size=3, max_len=3, name='msfSecurityModel', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x2f, 0x30, 0x2d]), size=4, max_len=4, name='msgAuthoritativeEngineID_header',
                fuzzable=False)
        s_bytes(value=bytes([0x04, 0x0d, 0x80, 0x00, 0x1f, 0x88]), size=6, max_len=6, name='Engine_Enterprise_ID',
                fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Engine_ID_Format', fuzzable=False)
        s_bytes(value=bytes([0x59, 0xdc, 0x48, 0x61]), size=4, max_len=4, name='Engine_ID_Data', fuzzable=False)
        s_bytes(value=bytes([0x45, 0xa2, 0x63, 0x22]), size=4, max_len=4, name='Engine_ID_Date1', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x01, 0x08]), size=3, max_len=3, name='msgAuthoritativeEngineBoots', fuzzable=False)
        s_bytes(value=bytes([0x02, 0X02, 0X0a, 0xb9]), size=4, max_len=4, name='msgAuthoritativeEngineTime',
                fuzzable=False)
        s_bytes(value=bytes([0x04, 0X05, 0X70, 0x59, 0x70, 0x70, 0x6f]), size=7, max_len=7, name='msgAUserName',
                fuzzable=False)
        s_bytes(value=bytes([0x04, 0X0c, 0X05, 0x5f, 0x0a, 0xa2, 0x18, 0xfd, 0x32, 0x5b, 0xbd, 0x0d, 0xea, 0xd6]),
                size=14, max_len=14, name='msgAuthenticationParameters', fuzzable=False)
        s_bytes(value=bytes([0x04, 0X00]), size=2, max_len=2, name='msgPrivacyParameters', fuzzable=False)
        s_bytes(value=bytes([0x30, 0X6c]), size=2, max_len=2, name='msgData_header', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x0d]), size=2, max_len=2, name='contextEngineID_header', fuzzable=False)
        s_bytes(value=bytes([0x80, 0X00, 0x1f, 0x88]), size=4, max_len=4, name='Engine_Enterprise_ID2', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Engine_ID_Format2', fuzzable=False)
        s_bytes(value=bytes([0x59, 0xdc, 0x48, 0x61]), size=4, max_len=4, name='Engine_ID_Data2', fuzzable=False)
        s_bytes(value=bytes([0x45, 0Xa2, 0x63, 0x22]), size=4, max_len=4, name='Engine_ID_Data3', fuzzable=False)
        s_bytes(value=bytes([0x04, 0X00]), size=2, max_len=2, name='contextName_header', fuzzable=False)
        s_bytes(value=bytes([0xa1, 0X59]), size=2, max_len=2, name='get_next_request_header', fuzzable=False)
        s_bytes(value=bytes([0x02, 0X04, 0x2c, 0x18, 0x0d, 0xbd]), size=6, max_len=6, name='request_id', fuzzable=False)
        s_bytes(value=bytes([0x02, 0X01, 0x00]), size=3, max_len=3, name='error_status', fuzzable=False)
        s_bytes(value=bytes([0x02, 0X01, 0x00]), size=3, max_len=3, name='error_index', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x4b]), size=2, max_len=2, name='variable_bindings_header', fuzzable=False)
        s_bytes(value=bytes(
            [0x30, 0X0d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x08, 0x05, 0x00, 0x30, 0x0d, 0x06,
             0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06,
             0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0c, 0x05, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01,
             0x02, 0x02, 0x01, 0x11, 0x05, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01,
             0x12, 0x05, 0x00]), size=75, max_len=75, name='Value', fuzzable=True)
    session.connect(s_get('snmpv3_get_next_request'))







if __name__ == "__main__":
    fuzzing_main()
