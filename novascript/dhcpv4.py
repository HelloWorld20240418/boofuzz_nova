interface_port=''


def fuzzing_main():
    session = Session(target=Target(RawL3SocketConnection(interface=interface_port, ethernet_proto=0x0800)), nova_session_param=nova_session_param)
    fuzzing_define_proto(session=session)
    session.fuzz()



def fuzzing_define_proto(session):
    s_initialize(name="Discover")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x01,0x2c]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0xa8,0x36]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0xfa]), size=1, max_len=1, name='Time to Live', fuzzable=False)
        s_bytes(value=bytes([0x11]), size=1, max_len=1, name='Protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff,0xff,0xff]), size=4, max_len=4, name='Destination Address', fuzzable=False)

    with s_block("UDP"):
        s_bytes(value=bytes([0x00, 0x44]), size=2, max_len=2, name='src_port', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x43]), size=2, max_len=2, name='dst_port', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x18]), size=2, max_len=2, name='length', fuzzable=False)
        s_checksum(block_name='UDP', algorithm='udp', name='Checksum',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)

    #with s_block("Dynamic_Host_Configuration_Protocol"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Message_type', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Hardware_type1', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Hardware_address_type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Hops', fuzzable=False)
        s_bytes(value=bytes([0xaf,0x0e,0xc7,0xef]), size=4, max_len=4, name='Transaction_ID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Seconds_elapsed', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Bootp_flags', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Client_IP_address', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Your_IP_address', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Next_server_IP_address', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Relay_agent_IP_address', fuzzable=False)
        s_bytes(value=bytes([0xa2, 0x01, 0xfb, 0x49,0x83,0x72]), size=6, max_len=6, name='Client_MAC_address1', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00]), size=6, max_len=6, name='Client_hardware_address_padding',fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00,0x00,0x00,0x00
                                 ]), size=64, max_len=64,name='Sever_host_name_not_given', fuzzable=True)
        s_bytes(value=bytes(
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00
                 ]), size=128, max_len=128, name='Boot_file_name_not_given', fuzzable=True)
        s_bytes(value=bytes([0x63,0x82,0x53,0x63]), size=4, max_len=4, name='Magic_cookie', fuzzable=False)
        s_bytes(value=bytes([0x35]), size=1, max_len=1, name='option1', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Length1', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='DHCP', fuzzable=False)
        s_bytes(value=bytes([0x3d]), size=1, max_len=1, name='option2', fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='Length2', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Hardware_type', fuzzable=False)
        #修改为客户端mac地址
        s_bytes(value=bytes([0xa2, 0x01, 0xfb, 0x49,0x83,0x72]), size=6, max_len=6, name='Client_MAC_address', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='option3', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Length3', fuzzable=False)
        s_bytes(value=bytes([0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74]), size=6, max_len=6, name='Host_name',fuzzable=False)
        s_bytes(value=bytes([0x37]), size=1, max_len=1, name='option4', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Length4', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='parameter_request_list_item', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='parameter_request_list_item1', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='option_end', fuzzable=False)
        s_bytes(value=bytes(
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=7, max_len=7, name='padding', fuzzable=False)


    s_initialize(name="Requst")
    with s_block("IPv4"):
        s_bytes(value=bytes([0x45]), size=1, max_len=1, name='Version', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='DSF', fuzzable=False)
        s_bytes(value=bytes([0x01,0x2c]), size=2, max_len=2, name='Total Length', fuzzable=False)
        s_bytes(value=bytes([0xa8,0x37]), size=2, max_len=2, name='Identification', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0xfa]), size=1, max_len=1, name='Time to Live', fuzzable=False)
        s_bytes(value=bytes([0x11]), size=1, max_len=1, name='Protocol', fuzzable=False)
        s_checksum("IPv4", algorithm='ipv4', name='Checksum', endian='>', length=2, fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Source Address', fuzzable=False)
        s_bytes(value=bytes([0xff,0xff,0xff,0xff]), size=4, max_len=4, name='Destination Address', fuzzable=False)
    with s_block("UDP"):
        s_bytes(value=bytes([0x00, 0x44]), size=2, max_len=2, name='src_port', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x43]), size=2, max_len=2, name='dst_port', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x18]), size=2, max_len=2, name='length', fuzzable=False)
        s_checksum(block_name='UDP', algorithm='udp', name='Checksum',
                   ipv4_src_block_name='Source Address', endian='>', ipv4_dst_block_name='Destination Address',
                   length=2, fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Message_type', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Hardware_type1', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='Hardware_address_type', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Hops', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x3d,0x1e]), size=4, max_len=4, name='Transaction_ID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Seconds_elapsed', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Bootp_flags', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Client_IP_address', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Your_IP_address', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Next_server_IP_address', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Relay_agent_IP_address', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0b, 0x82, 0x01,0xfc,0x42]), size=6, max_len=6, name='Client_MAC_address1', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00]), size=6, max_len=6, name='Client_hardware_address_padding',fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00,0x00,0x00,0x00
                                 ]), size=64, max_len=64,name='Sever_host_name_not_given', fuzzable=False)
        s_bytes(value=bytes(
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00
                 ]), size=128, max_len=128, name='Boot_file_name_not_given', fuzzable=False)
        s_bytes(value=bytes([0x63,0x82,0x53,0x63]), size=4, max_len=4, name='Magic_cookie', fuzzable=False)
        s_bytes(value=bytes([0x35]), size=1, max_len=1, name='option1', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Length1', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='DHCP', fuzzable=False)
        s_bytes(value=bytes([0x3d]), size=1, max_len=1, name='option2', fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='Length2', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Hardware_type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0b, 0x82, 0x01,0xfc,0x42]), size=6, max_len=6, name='Client_MAC_address', fuzzable=False)
        s_bytes(value=bytes([0x32]), size=1, max_len=1, name='option3', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Length3', fuzzable=False)
        s_bytes(value=bytes([0xc0, 0xa8, 0x00, 0x0a]), size=4, max_len=4, name='Requsted_IP_address',fuzzable=False)
        s_bytes(value=bytes([0x36]), size=1, max_len=1, name='option4', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Length4', fuzzable=False)
        s_bytes(value=bytes([0xc0,0xa8,0x00,0x01]), size=1, max_len=1, name='DHCP_Server_identifer', fuzzable=False)
        s_bytes(value=bytes([0x37]), size=1, max_len=1, name='parameter_request_list', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Length5', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='parameter_request_list_item', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='parameter_request_list_item1', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='parameter_request_list_item2', fuzzable=False)
        s_bytes(value=bytes([0x2a]), size=1, max_len=1, name='parameter_request_list_item3', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='option_end', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='padding', fuzzable=False)




        session.connect(s_get('Discover'))
        session.connect(s_get('Requst'))
if __name__ == "__main__":
            fuzzing_main()


