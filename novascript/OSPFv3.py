

interface_port = ''
src_ip = []
dst_ip = []


def fuzzing_main():
    session = Session(target=Target(connection=RawL3SocketConnection(interface=interface_port, ethernet_proto=0x86dd)),nova_session_param=nova_session_param)
    fuzzing_Ospfv3_update(session=session)
    session.fuzz()


def fuzzing_Ospfv3_update(session):
    s_initialize(name="OSPFV3_Update")
    with s_block("IPv6"):
        s_bytes(value=bytes([0x6c]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name='Traffic Class', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x84]), size=2, max_len=2, name='Payload Length', fuzzable=False)
        s_bytes(value=bytes([0x59]), size=1, max_len=1, name='Next Header', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Hop Limit', fuzzable=False)
        s_bytes(value=bytes(
            src_ip), size=16,
            max_len=16, name='Source Address', fuzzable=False)
        s_bytes(value=bytes(
            dst_ip), size=16,
            max_len=16, name='Destination Address', fuzzable=False)

    with s_block("ospfv3"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='ospf.msg', fuzzable=False)
        s_bytes(value=bytes([0x0a, 0x0a, 0x0a, 0x0a]), size=4, max_len=4, name='ospf.packet_length', fuzzable=False)
        s_bytes(value=bytes([0x0a, 0x0a, 0x0a, 0x0a]), size=4, max_len=4, name='ospf.area_id', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Hop Limit', fuzzable=False)
        s_checksum(block_name='ospfv3', algorithm='udp', name='Checksum_1',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        s_bytes(value=bytes([0x40]), size=1, max_len=1, name='ospf.instance_id', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='ospf.reserved_1', fuzzable=False)
    with s_block("ospfv3_1"):
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x02]), size=4, max_len=4, name='ospf.ls.number_of_lsas', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='ospf.lsa.age_1', fuzzable=False)
        s_bytes(value=bytes([0x20, 0x01]), size=2, max_len=2, name='ospf.v3.lsa_1', fuzzable=False)
        s_bytes(value=bytes([0x0a, 0x0a, 0x0a, 0x0a]), size=4, max_len=4, name='ospf.link_state_id', fuzzable=True)
        s_bytes(value=bytes([0x80, 0x00, 0x00, 0x1d]), size=4, max_len=4, name='ospf.link_state_id_2', fuzzable=True)
        s_checksum(block_name='ospfv3_1', algorithm='udp', name='Checksum_2',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        s_bytes(value=bytes([0x00, 0x28]), size=2, max_len=2, name='ospf.lsa.length_1', fuzzable=False)
        s_bytes(value=bytes([0x00]), name='ospf.v3.router.lsa.flags', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01, 0x32]), name='ospf.v3.options', fuzzable=False)
    with s_block("ospfv3_2"):
        s_bytes(value=bytes([0x02]), name='ospf.v3.lsa.type', fuzzable=False)
        s_bytes(value=bytes([0x00]), name='ospf.reserved_2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0a]), name='ospf.metric_1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x06]), name='ospf.v3.lsa.interface_id', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x06]), name='ospf.v3.lsa.neighbor_interface_id', fuzzable=True)
        s_bytes(value=bytes([0x0a, 0x0a, 0x0a, 0x0a]), name='ospf.v3.lsa.neighbor_router_id', fuzzable=True)

        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='ospf.lsa.age_2', fuzzable=False)
        s_bytes(value=bytes([0x20, 0x09]), name='ospf.v3.lsa_2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), name='ospf.link_state_id_3', fuzzable=False)
        s_bytes(value=bytes([0x0a, 0x0a, 0x0a, 0x0a]), name='ospf.advrouter', fuzzable=False)
        s_bytes(value=bytes([0x80, 0x00, 0x00, 0x02]), name='ospf.lsa.seqnum', fuzzable=False)
        s_checksum(block_name='ospfv3_2', algorithm='udp', name='Checksum_3',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        s_bytes(value=bytes([0x00, 0x30]), name='ospf.lsa.length_2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x02]), name='ospf.v3.lsa.num_prefixes', fuzzable=False)
        s_bytes(value=bytes([0x20, 0x01]), name='ospf.v3.lsa.referenced_ls_type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), name='Referenced Link State ID: 0.0.0.0', fuzzable=False)
        s_bytes(value=bytes([0x0a, 0x0a, 0x0a, 0x0a]), name='ospf.v3.lsa.referenced_advertising_router', fuzzable=True)
        s_bytes(value=bytes([0x20]), name='ospf.prefix_length_1', fuzzable=False)
        s_bytes(value=bytes([0x02]), name=' ospf.v3.prefix.options', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), name='ospf.metric_2', fuzzable=False)
        s_bytes(value=bytes([0x0a, 0x00, 0x00, 0x0a]), name='ospf.v3.address_prefix.ipv6_1', fuzzable=True)
        s_bytes(value=bytes([0x20]), name='ospf.prefix_length_2', fuzzable=False)
        s_bytes(value=bytes([0x02]), name='ospf.v3.prefix.options', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), name='ospf.metric_3', fuzzable=True)
        s_bytes(value=bytes([0xac, 0x10, 0x00, 0x0a]), name='ospf.v3.address_prefix.ipv6_2', fuzzable=True)
    session.connect(s_get('OSPFV3_Update'))


if __name__ == "__main__":
    fuzzing_main()
