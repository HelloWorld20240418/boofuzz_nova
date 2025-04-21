

host_ip = ''
host_port = 2123


def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)),nova_session_param=nova_session_param)

    fuzzing_define_proto(session=session)

    session.fuzz()


def fuzzing_define_proto(session):
    s_initialize(name="Create_pdp_context_request")
    with s_block("GPRS"):
        s_bytes(value=bytes([0x32]), size=1, max_len=1, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0x10]), size=1, max_len=1, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x8a]), size=2, max_len=2, name='length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='TEID', fuzzable=False)
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='Sequence_number', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x02,0x05,0x05,0x42,0x01,0x21,0x51,0x70,0x00]), size=11, max_len=11, name='IMSI', fuzzable=True)
        s_bytes(value=bytes([0x03,0x11,0xf1,0x22]), size=4, max_len=4, name='RAI', fuzzable=False)
        s_bytes(value=bytes([0x00,0x21]), size=2, max_len=2, name='location_area_code', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='routing_Area_code', fuzzable=False)
        s_bytes(value=bytes([0x0e,0x01]), size=2, max_len=2, name='recovery', fuzzable=False)
        s_bytes(value=bytes([0x0f,0x00,0x10]), size=3, max_len=3, name='Selection_mode', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x03,0xe8]), size=4, max_len=4, name='TEID_Date_I', fuzzable=True)
        s_bytes(value=bytes([0x11,0x00,0x00,0x00,0x01]), size=5, max_len=5, name='TETD_control_plane', fuzzable=False)
        s_bytes(value=bytes([0x14]), size=1, max_len=1, name='NSAPI', fuzzable=False)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='NSAPI_1', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='End_user_address', fuzzable=False)
        s_bytes(value=bytes([0x00,0x02]), size=2, max_len=2, name='Length', fuzzable=False)
        s_bytes(value=bytes([0xf1]), size=1, max_len=1, name='PDP_type_organization', fuzzable=False)
        s_bytes(value=bytes([0x21]), size=1, max_len=1, name='PDP_type_number', fuzzable=False)
        s_bytes(value=bytes([0x83]), size=1, max_len=1, name='ACCESS_point_name_harder', fuzzable=False)
        s_bytes(value=bytes([0x00,0x18]), size=2, max_len=2, name='APN_length', fuzzable=False)
        s_bytes(value=bytes([0x05,0x66,0x72,0x61,0x6e,0x6b,0x04,0x74,0x65,0x73,0x74,0x07
                             ,0x6e,0x65,0x74,0x77,0x6f,0x72,0x6b,0x04,0x67,0x70,0x72,0x73]), size=24, max_len=24, name='APN', fuzzable=True)
        s_bytes(value=bytes([0x85]), size=1, max_len=1, name='GSN_address_harder', fuzzable=False)
        s_bytes(value=bytes([0x00,0x04]), size=2, max_len=2, name='GSN_address_length', fuzzable=False)
        s_bytes(value=bytes([0x11,0x01,0x02,0x02]), size=4, max_len=4, name='GSN_address_IPV4', fuzzable=True)
        s_bytes(value=bytes([0x85]), size=1, max_len=1, name='GSN_address_harder1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name='GSN_address_length1', fuzzable=False)
        s_bytes(value=bytes([0x11, 0x01, 0x02, 0x02]), size=4, max_len=4, name='GSN_address_IPV41', fuzzable=True)
        s_bytes(value=bytes([0x86]), size=1, max_len=1, name='MS_international_harder', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x07]), size=2, max_len=2, name='S_international_length', fuzzable=False)
        s_bytes(value=bytes([0x91]), size=1, max_len=1, name='EXTENSION', fuzzable=False)
        s_bytes(value=bytes([0x71,0x69,0x42,0x08,0x41,0xf1]), size=6, max_len=6, name='E.164_number', fuzzable=False)
        s_bytes(value=bytes([0x87]), size=1, max_len=1, name='quality_harder', fuzzable=False)
        s_bytes(value=bytes([0x00,0x0c]), size=2, max_len=2, name='quality_length', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Allocation/Retention priority', fuzzable=False)
        s_bytes(value=bytes([0x09]), size=1, max_len=1, name='spare', fuzzable=False)
        s_bytes(value=bytes([0x11]), size=1, max_len=1, name='Qos_peak', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='spare1', fuzzable=False)
        s_bytes(value=bytes([0x29]), size=1, max_len=1, name='Traffic_class', fuzzable=False)
        s_bytes(value=bytes([0x0a]), size=1, max_len=1, name='Maximum_sdu_size', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Maximum_bit_rate_for_uplink', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Maximum_bit_rate_for_downlink', fuzzable=False)
        s_bytes(value=bytes([0x11]), size=1, max_len=1, name='Residual_ber', fuzzable=False)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Transfer_delay', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Guarateed_bit_rate_for_uplink', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Guarateed_bit_rate_for_downlink', fuzzable=False)
        s_bytes(value=bytes([0x97]), size=1, max_len=1, name='Rat_type_harder', fuzzable=False)
        s_bytes(value=bytes([0x00,0x01]), size=2, max_len=2, name='Rat_type_length', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Rat_type', fuzzable=False)
        s_bytes(value=bytes([0x98]), size=1, max_len=1, name='User_Location_Information_harder', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='ULI_length', fuzzable=False)
        s_bytes(value=bytes([0x00,0x11,0xf1,0x22]), size=4, max_len=4, name='Geographic_loc_type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x21]), size=2, max_len=2, name='location_area_code1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name='Cell_ID', fuzzable=False)
        s_bytes(value=bytes([0x99]), size=1, max_len=1, name='MS_TIME_zone_harder', fuzzable=False)
        s_bytes(value=bytes([0x00,0x02]), size=2, max_len=2, name='MS_TIME_zone_length', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='TIME_zone', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='DST', fuzzable=False)
        s_bytes(value=bytes([0x9a]), size=1, max_len=1, name='IMEI_harder', fuzzable=False)
        s_bytes(value=bytes([0x00,0x08]), size=2, max_len=2, name='IMEI_length', fuzzable=False)
        s_bytes(value=bytes([0x32,0x54,0x76,0x98,0x21,0x43,0x65,0x30]), size=8, max_len=8, name='IMEI', fuzzable=False)

    s_initialize(name="Delete_pdp_context_request")
    with s_block("GPRS"):
        s_bytes(value=bytes([0x32]), size=1, max_len=1, name='Flags', fuzzable=False)
        s_bytes(value=bytes([0x14]), size=1, max_len=1, name='message_type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='length', fuzzable=True)
        s_bytes(value=bytes([0x00,0x0f,0x42,0x40]), size=4, max_len=4, name='TEID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name='Sequence_number', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x13,0xff]), size=4, max_len=4, name='Teardowm_Indicator', fuzzable=True)
        s_bytes(value=bytes([0x14,0x05,0x00,0x00]), size=4, max_len=4, name='NSAPI', fuzzable=False)





        session.connect(s_get('Create_pdp_context_request'))
        session.connect(s_get('Delete_pdp_context_request'))





if __name__ == "__main__":
    fuzzing_main()