
host_ip = ''
host_port = 830

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)
    fuzzing_Protocol(session=session)
    session.fuzz()


def fuzzing_Protocol(session):
    s_initialize(name="Protocol")
    with s_block("Protocol"):
        s_bytes(value=bytes([0x53,0x53,0x48,0x2d,0x32,0x2e,0x30,0x2d,0x70,0x61,0x72,0x61,0x6d,0x69,0x6b,0x6f,0x5f,0x33,0x2e,0x34,0x2e,0x30,0x0d,0x0a]), size=24, max_len=24, name='tcp_payload1', fuzzable=True)
    s_initialize(name="XML")
    with s_block("XML"):
        s_delim("  ", name="space", fuzzable=False)
        s_string("<config>",name='comnfig')
        s_static("\r\n", name="Line-CRLF")
        s_delim("      ", name="space-1", fuzzable=False)
        s_string("<vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">", name='vlan')
        s_static("\r\n", name="Line-CRLF2")
        s_delim("        ", name="space-2", fuzzable=False)
        s_static(value="<vlans>", name="vlans")
        s_static("\r\n", name="Line-CRLF3")
        s_delim("           ", name="space-3", fuzzable=False)
        s_static(value="<vlan>", name="vlan_2")
        s_static("\r\n", name="Line-CRLF4")
        s_delim("              ", name="space-4", fuzzable=False)
        s_string("<vlanId>100</vlanId>",name='vlanid')
        s_static("\r\n", name="Line-CRLF5")
        s_delim("              ", name="space-5", fuzzable=False)
        s_string("<vlanif operation=\"create\">", name='vlanif')
        s_static("\r\n", name="Line-CRLF6")
        s_delim("                ", name="space-6", fuzzable=False)
        s_string("<cfgBand>1</cfgBand>", name='cfgBand')
        s_static("\r\n", name="Line-CRLF7")
        s_delim("                ", name="space-7", fuzzable=False)
        s_string("<dampTime>0</dampTime>", name='dampTime')
        s_static("\r\n", name="Line-CRLF8")
        s_delim("              ", name="space-8", fuzzable=False)
        s_string("</vlanif>", name='vlanif_2')
        s_static("\r\n", name="Line-CRLF9")
        s_delim("           ", name="space-9", fuzzable=False)
        s_static(value="<vlan>", name="vlan_3")
        s_static("\r\n", name="Line-CRLF10")
        s_delim("        ", name="space-10", fuzzable=False)
        s_static(value="<vlans>", name="vlans_2")
        s_static("\r\n", name="Line-CRLF11")
        s_delim("      ", name="space-11", fuzzable=False)
        s_string("<vlan>", name='vlan_4')
        s_static("\r\n", name="Line-CRLF12")
        s_delim("      ", name="space-12", fuzzable=False)
        s_string("</config>'''", name='/config')

    session.connect(s_get('Protocol'))
    session.connect(s_get('Protocol'), s_get('XML'))




if __name__ == "__main__":
    fuzzing_main()
