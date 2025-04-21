host_ip = ''
host_port = 179

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param )
    fuzzing_BGP_OPEN_Message(session=session)
    fuzzing_UPDATE(session=session)

    session.fuzz()



    # ---------- BGP OPEN Message ---------- #
def fuzzing_BGP_OPEN_Message(session):
    s_initialize(name="BGP_OPEN_Message")
    with s_block("BGP"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="marker", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x3f]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name="type", fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="version", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x64]), size=2, max_len=2, name="my as", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x5a]), size=2, max_len=2, name="hold time", fuzzable=False)
        s_bytes(value=bytes([0xc0, 0xa8, 0x00, 0x0f]), size=4, max_len=4, name="BGP Identifier")
        s_bytes(value=bytes([0x22]), size=1, max_len=1, name="optional parameters length", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="parameter_type", fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name="bgp.open.opt.param.len", fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name="parameter_type2", fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="bgp.open.opt.param.len2", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x19]), size=2, max_len=2, name="AFI", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_bytes(value=bytes([0x46]), size=1, max_len=1, name="SAFI", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="parameter_type3", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="bgp.open.opt.param.len3", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="parameter_type4", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="bgp.open.opt.param.len4", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="parameter_type5", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="bgp.open.opt.param.len5", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="parameter_type6", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="bgp.open.opt.param.len6", fuzzable=False)
        s_bytes(value=bytes([0x02, 0x02, 0x40, 0x02,0x40,0x78]), size=6, max_len=6, name="bgp.open.opt.param", fuzzable=True)
        s_bytes(value=bytes([0x02, 0x06, 0x41, 0x04,0x00,0x00,0x00,0x64]), size=8, max_len=8, name="bgp.open.opt.param2", fuzzable=True)
        s_bytes(value=bytes([0x02, 0x02, 0x47, 0x00]), size=4, max_len=4, name="bgp.open.opt.param3", fuzzable=True)
def fuzzing_UPDATE(session):
    s_initialize(name="UPDATE")
    with s_block("BGP"):
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff]), size=16, max_len=16, name="marker", fuzzable=True)
        s_bytes(value=bytes([0x00, 0xa3]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="type", fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name="bgp.update.withdrawn_routes.length", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x8c]), size=2, max_len=2, name="bgp.update.path_attributes.length", fuzzable=False)
    with s_block("path_attrobutes"):
        s_bytes(value=bytes([0x90]), size=1, max_len=1, name="flags", fuzzable=False)
        s_bytes(value=bytes([0x0f]), size=1, max_len=1, name="Tpye_code", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x88]), size=2, max_len=2, name="length", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x19]), size=2, max_len=2, name="bgp.update.path_attribute.mp_unreach_nlri.afi", fuzzable=False)
        s_bytes(value=bytes([0x46]), size=1, max_len=1, name="EVPN", fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name="bgp.evpn.nlri.rt", fuzzable=False)
        s_bytes(value=bytes([0x19]), size=1, max_len=1, name="bgp.evpn.nlri.len", fuzzable=False)
        s_bytes(value=bytes([0x00,0x01,0x78,0x00,0x02,0x01,0x00,0x64]), size=8, max_len=8, name="bgp.evpn.nlri.rd", fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x05]), size=10, max_len=10, name="ESI", fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name="ETID", fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00]), size=3, max_len=3, name="bgp.evpn.nlri.mpls_ls1", fuzzable=False)
    with s_block("EVPN_NLRI2"):
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="ROUTE_TYPE", fuzzable=False)
        s_bytes(value=bytes([0x17]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0x00,0x01,0x78,0x00,0x02,0x01,0x00,0x00]), size=8, max_len=8, name="bgp.evpn.nlri.rd", fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x05]), size=10, max_len=10, name="ESI", fuzzable=True)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name="IPADDRESS", fuzzable=False)
        s_bytes(value=bytes([0x78,0x00,0x02,0x01]), size=4, max_len=4, name="ipv4.address", fuzzable=False)
    with s_block("EVPN_NLRI3"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROUTE_TYPE", fuzzable=False)
        s_bytes(value=bytes([0x19]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01, 0x78, 0x00, 0x02, 0x01, 0x00, 0x00]), size=8, max_len=8,
                name="bgp.evpn.nlri.rd", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05]), size=10, max_len=10,
                name="ESI", fuzzable=False)
        s_bytes(value=bytes([0xff, 0xff, 0xff, 0xff]), size=4, max_len=4, name="ETID", fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00]), size=3, max_len=3, name="bgp.evpn.nlri.mpls_ls1", fuzzable=False)
    with s_block("EVPN_NLRI4"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="ROUTE_TYPE", fuzzable=False)
        s_bytes(value=bytes([0x11]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01, 0x78, 0x00, 0x02, 0x01, 0x00, 0x64]), size=8, max_len=8,
                name="bgp.evpn.nlri.rd", fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00, 0x64]), size=4, max_len=4, name="ETID", fuzzable=False)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name="IPADDRESS", fuzzable=False)
        s_bytes(value=bytes([0x78, 0x00, 0x02, 0x01]), size=4, max_len=4, name="ipv4.address", fuzzable=False)
    with s_block("EVPN_NLRI_mac"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="ROUTE_TYPE", fuzzable=False)
        s_bytes(value=bytes([0x21]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01, 0x78, 0x00, 0x02, 0x01, 0x00, 0x64]), size=8, max_len=8,
                name="bgp.evpn.nlri.rd", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=10, max_len=10, name="ESI", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x64]), size=4, max_len=4, name="ETID", fuzzable=False)
        s_bytes(value=bytes([0x30]), size=1, max_len=1, name="macIPADDRESS", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=6, max_len=6, name="ipv4.address", fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="iPADDRESS", fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00]), size=3, max_len=3, name="bgp.evpn.nlri.mpls_ls1", fuzzable=False)
    session.connect(s_get('BGP_OPEN_Message'))
    session.connect(s_get('BGP_OPEN_Message'),s_get('UPDATE'))

if __name__ == "__main__":
    fuzzing_main()
