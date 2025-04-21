
host_ip = ''
host_port = 445

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_Negotiate_protocol_Request(session=session)
    fuzzing_session_SETUP_ADNX_REQUEST(session=session)
    fuzzing_session_SETUP_ADNX_REQUEST_AUTH(session=session)
    fuzzing_Tree_Connect_AdnX_Request(session=session)
    fuzzing_Delete_Request(session=session)
    fuzzing_NT_Create_AndX_Request(session=session)
    fuzzing_Create_Directory_Request(session=session)
    fuzzing_Check_Directoru_Request(session=session)
    fuzzing_Open_Requst(session=session)
    fuzzing_IOCTL_Request(session=session)
    fuzzing_Read_AndX_Request(session=session)
    fuzzing_Write_AndX_Request(session=session)
    fuzzing_Logoff_AndX_Request(session=session)
    fuzzing_Locking_AndX_Request(session=session)
    fuzzing_Unlock_Byte_Range_Request(session=session)
    fuzzing_lock_Byte_Range_Request(session=session)
    fuzzing_Query_Information_Disk_Request(session=session)
    fuzzing_Find_Request(session=session)
    fuzzing_Find_Close_Request(session=session)
    fuzzing_Find_Unique_Request(session=session)
    fuzzing_Search_Request(session=session)
    fuzzing_Trans2_Request(session=session)
    fuzzing_Set_Information2_Request(session=session)
    fuzzing_Query_Information2_Request(session=session)
    fuzzing_Tran_Disconnect_Request(session=session)
    fuzzing_Rename_Request(session=session)
    fuzzing_NT_Rename_Request(session=session)
    fuzzing_Close_Request(session=session)
    fuzzing_Process_Exit_Requst(session=session)
    session.fuzz()

def fuzzing_Negotiate_protocol_Request(session):
    s_initialize(name="Negotiate_protocol_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0xdb]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff,0x53,0x4d,0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x72]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x43,0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='User_ID', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xb8, 0x00]), size=2, max_len=2, name='Byte_count', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes([0x50,0x43,0x20,0x4e,0x45,0x54,0x57,0x4f,0x52,0x4b,0x20,0x50,0x52,0x4f,0x47,0x52,0x41
                            ,0x4d,0x20,0x31,0x2e,0x30,0x00]), size=23, max_len=23, name='Name', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format1', fuzzable=False)
        s_bytes(value=bytes([0x4d,0x49,0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53
                , 0x20, 0x31,  0x2e, 0x30, 0x33,0x00]), size=24, max_len=24, name='Name1', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format2', fuzzable=False)
        s_bytes(value=bytes([0x4d,0x49,0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53
                , 0x20, 0x31,  0x2e, 0x30, 0x00]), size=23, max_len=23, name='Name2', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format3', fuzzable=False)
        s_bytes(value=bytes([0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x31,0x2e,0x30,0x00]), size=10, max_len=10, name='Name3', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format4', fuzzable=False)
        s_bytes(value=bytes([0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72
            , 0x6f, 0x75, 0x70, 0x73, 0x20,0x33,0x2e,0x31,0x61,0x00]), size=28, max_len=28, name='Name4', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format5', fuzzable=False)
        s_bytes(value=bytes([0x4c,0x4d,0x31,0x2e,0x32,0x58,0x30,0x30,0x32,0x00]), size=10, max_len=10, name='Name5', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format6', fuzzable=False)
        s_bytes(value=bytes([0x44,0x4f,0x53,0x20,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x32,0x2e,0x31,0x00]), size=14, max_len=14, name='Name6', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format7', fuzzable=False)
        s_bytes(value=bytes([0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x32,0x2e,0x31,0x00]), size=10, max_len=10, name='Name7', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format8', fuzzable=False)
        s_bytes(value=bytes([0x53,0x61,0x6d,0x62,0x61,0x00]), size=6, max_len=6, name='Name8', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format9', fuzzable=False)
        s_bytes(value=bytes([0x4e,0x54,0x20,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x20,0x31,0x2e,0x30,0x00]), size=14, max_len=14, name='Name9', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Buffer_format10', fuzzable=False)
        s_bytes(value=bytes([0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00]), size=11, max_len=11, name='Name10', fuzzable=True)
        session.connect(s_get('Negotiate_protocol_Request'))

def fuzzing_session_SETUP_ADNX_REQUEST(session):
    s_initialize(name="session_SETUP_ADNX_REQUEST")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0xd4]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x73]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Andxcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='adnxoffset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x30]), size=2, max_len=2, name='MAX_Buffer', fuzzable=False)
        s_bytes(value=bytes([0x32, 0x00]), size=2, max_len=2, name='MAx_MPX_COUNT', fuzzable=False)
        s_bytes(value=bytes([0x01,0x00]), size=2, max_len=2, name='vc_number', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00, 0x00]), size=4, max_len=4, name='Session_key', fuzzable=False)
        s_bytes(value=bytes([0x4a, 0x00]), size=2, max_len=2, name='Security_Blob_length', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x00]), size=4, max_len=4, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0xfd,0xe3,0x03, 0x80]), size=4, max_len=4, name='Capabilities', fuzzable=False)
        s_bytes(value=bytes([0x99, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
        s_bytes(value=bytes([0x60,0x48,0x06,0x06]), size=4, max_len=4, name='Security_BLOb', fuzzable=False)
        s_bytes(value=bytes([0x2b,0x06,0x01,0x05,0x05,0x02]), size=6, max_len=6, name='OID', fuzzable=False)
        s_bytes(value=bytes([0xa0,0x3e]), size=2, max_len=2, name='SPN_harder', fuzzable=False)
        s_bytes(value=bytes([0x30,0x3c,0xa0,0x0e,0x30,0x0c]), size=6, max_len=6, name='mechtypes', fuzzable=False)
        s_bytes(value=bytes([0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a]), size=12, max_len=12, name='mechtype', fuzzable=True)
        s_bytes(value=bytes([0xa2,0x2a,0x04,0x28,0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x15,0x02,0x08
                             ,0x60,0x05,0x00,0x05,0x00,0x20,0x00,0x00,0x00,0x03,0x00,0x03,0x00,0x25,0x00,0x00,0x00,0x56,0x4e
                             ,0x45,0x54,0x33,0x42,0x4c,0x55]), size=44, max_len=44, name='mechtoken', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x55,0x00,0x6e,0x00,0x69,0x00,0x78,0x00,0x00,0x00]), size=11, max_len=11, name='Native_OS', fuzzable=False)
        s_bytes(value=bytes([0x53,0x00,0x61,0x00,0x6d,0x00,0x62,0x00,0x61,0x00,0x20,0x00,0x33,0x00,0x2e,0x00,
                             0x39,0x00,0x2e,0x00,0x30,0x00,0x2d,0x00,0x53,0x00,0x56,0x00,0x4e,0x00,0x2d,0x00,0x62,0x00,0x75,0x00,0x69
                             ,0x00,0x6c,0x00,0x64,0x00,0x2d,0x00,0x31,0x00,0x31,0x00,0x35,0x00,0x37,0x00,0x32,0x00,0x00,0x00]), size=56, max_len=56, name='Native_LAN_Manager', fuzzable=False)
        s_bytes(value=bytes([ 0x56,0x00, 0x4e, 0x00, 0x45, 0x00, 0x54, 0x00, 0x33, 0x00, 0x00,0x00]), size=12, max_len=12, name='Primary_domain', fuzzable=True)
        session.connect(s_get('session_SETUP_ADNX_REQUEST'))


def fuzzing_session_SETUP_ADNX_REQUEST_AUTH(session):
    s_initialize(name="session_SETUP_ADNX_REQUEST_AUTH")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01, 0x40]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x73]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                    fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x03, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Andxcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='adnxoffset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x30]), size=2, max_len=2, name='MAX_Buffer', fuzzable=False)
        s_bytes(value=bytes([0x32, 0x00]), size=2, max_len=2, name='MAx_MPX_COUNT', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='vc_number', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Session_key', fuzzable=False)
        s_bytes(value=bytes([0xb6, 0x00]), size=2, max_len=2, name='Security_Blob_length', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0xfd, 0xe3, 0x03, 0x80]), size=4, max_len=4, name='Capabilities', fuzzable=False)
        s_bytes(value=bytes([0x05, 0x01]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
        s_bytes(value=bytes([0xa1,0x81,0xb3]), size=3, max_len=3, name='Security_BLOb', fuzzable=False)
        s_bytes(value=bytes([0x30, 0x81, 0xb0, 0xa2, 0x81, 0xad,0x04,0x81,0xaa]), size=9, max_len=9, name='mechtypes', fuzzable=False)
        s_bytes(value=bytes( [0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00]), size=8, max_len=8, name='NTLMSSP_IDentifier', fuzzable=False)
        s_bytes(value=bytes([0x03,0x00,0x00,0x00]), size=4, max_len=4, name='NTLM_message_type', fuzzable=False)
        s_bytes(value=bytes([0x18,0x00]), size=2, max_len=2, name='LMR_length', fuzzable=False)
        s_bytes(value=bytes([0x18,0x00]), size=2, max_len=2, name='LMR_maxlen', fuzzable=False)
        s_bytes(value=bytes([0x40,0x00,0x00,0x00]), size=4, max_len=4, name='LMR_offset', fuzzable=False)
        s_bytes(value=bytes([0x18, 0x00]), size=2, max_len=2, name='NR_length', fuzzable=False)
        s_bytes(value=bytes([0x18,0x00]), size=2, max_len=2, name='NR_MAXLEN', fuzzable=False)
        s_bytes(value=bytes([0x58,0x00,0x00,0x00]), size=4, max_len=4, name='NR_offset', fuzzable=False)
        s_bytes(value=bytes([0x0a,0x00]), size=2, max_len=2, name='Dn_length', fuzzable=False)
        s_bytes(value=bytes([0x0a,0x00]), size=2, max_len=2, name='Dn_MAXLEN', fuzzable=False)
        s_bytes(value=bytes([0x70,0x00,0x00,0x00]), size=4, max_len=4, name='Dn_offset', fuzzable=False)
        s_bytes(value=bytes([0x1a,0x00]), size=2, max_len=2, name='Un_length', fuzzable=False)
        s_bytes(value=bytes([0x1a,0x00]), size=2, max_len=2, name='Un_MAXLEN', fuzzable=False)
        s_bytes(value=bytes([0x7a,0x00, 0x00, 0x00]), size=4, max_len=4, name='Un_offset', fuzzable=False)
        s_bytes(value=bytes([0x06,0x00]), size=2, max_len=2, name='Hn_length', fuzzable=False)
        s_bytes(value=bytes([0x06,0x00]), size=2, max_len=2, name='Hn_MAXLEN', fuzzable=False)
        s_bytes(value=bytes([0x94,0x00,0x00,0x00]), size=4, max_len=4, name='Hn_offset', fuzzable=False)
        s_bytes(value=bytes([0x10,0x00]), size=2, max_len=2, name='Sk_length', fuzzable=False)
        s_bytes(value=bytes([0x10,0x00]), size=2, max_len=2, name='Sk_MAXLEN', fuzzable=False)
        s_bytes(value=bytes([0x9a,0x00,0x00, 0x00]), size=4, max_len=4, name='SK_offset', fuzzable=False)
        s_bytes(value=bytes([0x15,0x02,0x08,0x60]), size=4, max_len=4, name='negotiate_flags', fuzzable=False)
        s_bytes(value=bytes([0x42,0xc0,0x9b,0x26,0x4c,0xbc,0x46,0x69]), size=8, max_len=8, name='LMv2_client_challenge', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,]), size=16, max_len=16,name='Lan_manager_response', fuzzable=False)
        s_bytes(value=bytes([ 0x9c,0xd7,0xe4,0xaf,0x2d,0x7e,0x93,0x4a,0xdc,0x9b,0x30,0x72,0x31,0xa9,0x58,0x53,0x9b,0x3d,0x2c,0x36,0x8b,0x96,0x4c,0xea]), size=24, max_len=24,name='NTLMR', fuzzable=False)
        s_bytes(value=bytes([0x56,0x00,0x4e,0x00,0x45,0x00,0x54,0x00,0x33,0x00]), size=10, max_len=10, name='Domain_name', fuzzable=False)
        s_bytes(value=bytes([0x61,0x00,0x64,0x00,0x6d,0x00,0x69,0x00,0x6e,0x00,0x69,0x00,0x73,0x00,0x74,0x00,0x72,0x00,0x61,0x00,
                 0x74,0x00,0x6f,0x00,0x72,0x00]), size=26, max_len=26, name='user_name', fuzzable=False)
        s_bytes(value=bytes([0x42,0x00,0x4c,0x00,0x55,0x00]), size=6, max_len=6, name='host_name', fuzzable=False)
        s_bytes(value=bytes([0x27,0xa3,0x71,0xf8,0x2c,0x27,0xe3,0x00,0x53,0x74,0xd8,0xe8,0xd1,0xeb,0xb9,0x50]), size=2, max_len=2, name='Session_KEY', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x55, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x78, 0x00, 0x00, 0x00]), size=11,
                    max_len=11, name='Native_OS', fuzzable=False)
        s_bytes(value=bytes(
                [0x53, 0x00, 0x61, 0x00, 0x6d, 0x00, 0x62, 0x00, 0x61, 0x00, 0x20, 0x00, 0x33, 0x00, 0x2e, 0x00,
                 0x39, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2d, 0x00, 0x53, 0x00, 0x56, 0x00, 0x4e, 0x00, 0x2d, 0x00, 0x62,
                 0x00, 0x75, 0x00, 0x69
                    , 0x00, 0x6c, 0x00, 0x64, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x31, 0x00, 0x35, 0x00, 0x37, 0x00, 0x32,
                 0x00, 0x00, 0x00]), size=56, max_len=56, name='Native_LAN_Manager', fuzzable=False)
        s_bytes(value=bytes([0x56, 0x00, 0x4e, 0x00, 0x45, 0x00, 0x54, 0x00, 0x33, 0x00, 0x00, 0x00]), size=12,
                    max_len=12, name='Primary_domain', fuzzable=True)
        session.connect(s_get('session_SETUP_ADNX_REQUEST_AUTH'))


def fuzzing_Tree_Connect_AdnX_Request(session):
    s_initialize(name="Tree_Connect_AdnX_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x60]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x75]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x04, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Andxcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='adnxoffset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Flages3', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='password_length', fuzzable=False)
        s_bytes(value=bytes([0x35, 0x00]), size=2, max_len=2, name='Path', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='password', fuzzable=False)
        s_bytes(value=bytes([0x5c,0x00,0x5c,0x00,0x31,0x00,0x39,0x00,0x32,0x00,0x2e,0x00,0x31,0x00,0x36,0x00,0x38,0x00,0x2e,
                             0x00,0x31,0x00,0x39,0x00,0x32,0x00,0x2e,0x00,0x31,0x00,0x32,0x00,0x39,0x00,0x5c,0x00,0x54,0x00,
                             0x45,0x00,0x53,0x00,0x54,0x00,0x00,0x00]), size=46, max_len=46, name='path', fuzzable=True)
        s_bytes(value=bytes([0x3f,0x3f,0x3f,0x3f,0x3f,0x00]), size=6, max_len=6, name='Service', fuzzable=False)
    session.connect(s_get('Tree_Connect_AdnX_Request'))

def fuzzing_Process_Exit_Requst(session):
    s_initialize("Process_Exit_Requst")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x23]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x11]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x05, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
    session.connect(s_get('Process_Exit_Requst'))


def fuzzing_Delete_Request(session):
    s_initialize(name="Delete_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x54]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x06]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x05, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x16, 0x00]), size=2, max_len=2, name='search_attributes', fuzzable=False)
        s_bytes(value=bytes([0x2f, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='buffer_format', fuzzable=False)
        s_bytes(value=bytes([0x5c,0x00,0x74,0x00,0x6f,0x00,0x72,0x00,0x74,0x00,0x75,0x00,0x72,0x00,0x65,0x00,0x5f,0x00,0x71,
                             0x00,0x66,0x00,0x69,0x00,0x6c,0x00,0x65,0x00,0x69,0x00,0x6e,0x00,0x66,0x00,0x6f,0x00,0x2e,0x00,
                             0x74,0x00,0x78,0x00,0x74,0x00,0x00,0x00]), size=46, max_len=46, name='file_name', fuzzable=False)
    session.connect(s_get('Delete_Request'))

def fuzzing_NT_Create_AndX_Request(session):
    s_initialize(name="NT_Create_AndX_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x82]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0xa2]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x06, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x18]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='andXcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Andxoffset', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved2', fuzzable=False)
        s_bytes(value=bytes([0x2c, 0x00]), size=2, max_len=2, name='file_name_len', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='create_flags', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='root_fid', fuzzable=False)
        s_bytes(value=bytes([0xff, 0x01, 0x1f, 0x00]), size=4, max_len=4, name='Access_Mask', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Allocation_size', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='File_attributes', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='share_access', fuzzable=False)
        s_bytes(value=bytes([0x07, 0x00, 0x00, 0x00]), size=4, max_len=4, name='root_fid1', fuzzable=False)
        s_bytes(value=bytes([0x05, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Disposition', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Create_Options', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Impersonation', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Security_flags', fuzzable=False)
        s_bytes(value=bytes([0x2f, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
        s_bytes(value=bytes(
            [0x5c, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00, 0x5f, 0x00,
             0x71,
             0x00, 0x66, 0x00, 0x69, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x66, 0x00, 0x6f, 0x00, 0x2e,
             0x00,
             0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x00, 0x00]), size=46, max_len=46, name='file_name', fuzzable=True)
    session.connect(s_get('NT_Create_AndX_Request'))

def fuzzing_Create_Directory_Request(session):
    s_initialize(name="Create_Directory_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x56]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=False)
        s_bytes(value=bytes([0x0f, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x33, 0x00]), size=2, max_len=2, name='Byte_count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes(
            [0x5c, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00,
             0x5f, 0x00, 0x6e, 0x00,0x6f,0x00, 0x74, 0x00, 0x69, 0x00,
             0x66, 0x00, 0x79, 0x00, 0x5c, 0x00, 0x73, 0x00, 0x75, 0x00,
             0x62, 0x00, 0x64, 0x00, 0x69, 0x00, 0x72, 0x00,0x2d, 0x00,
             0x6e, 0x00,0x61,0x00,0x6d,0x00,0x65,0x00,0x00,0x00]), size=50, max_len=50, name='Directory', fuzzable=True)

    session.connect(s_get('Create_Directory_Request'))



def fuzzing_Check_Directoru_Request(session):
    s_initialize(name="Check_Directoru_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x34]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x10]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=False)
        s_bytes(value=bytes([0x2e, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x11, 0x00]), size=2, max_len=2, name='Byte_count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes([0x5c,0x00,0x2e,0x00,0x5c,0x00,0x5c,0x00,0x78,0x00,0x78,0x00,0x78,0x00,0x00,0x00]), size=16, max_len=16, name='Directory', fuzzable=True)
    session.connect(s_get('Check_Directoru_Request'))




def fuzzing_Open_Requst(session):
    s_initialize(name="Open_Requst")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x6a]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x2d]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x16, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x0f]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Andxcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='AndXoffset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=1, max_len=1, name='flags3', fuzzable=False)
        s_bytes(value=bytes([0x42, 0x00]), size=1, max_len=1, name='Desired_Access', fuzzable=False)
        s_bytes(value=bytes([0x06, 0x00]), size=1, max_len=1, name='Search_attributes', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=1, max_len=1, name='File_attributes', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Created', fuzzable=False)
        s_bytes(value=bytes([0x11, 0x00]), size=2, max_len=2, name='Open_Function', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Allocation_size', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='timeout', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x29, 0x00,0x00]), size=3, max_len=3, name='Byte_count', fuzzable=False)
        s_bytes(value=bytes(
        [0x5c, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x5f, 0x00, 0x6d, 0x00, 0x75, 0x00, 0x78, 0x00,
         0x5c, 0x00, 0x77, 0x00, 0x72, 0x00, 0x69, 0x00, 0x64, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x61, 0x00,
         0x74,0x00, 0x00, 0x00]), size=40, max_len=40, name='File_Name', fuzzable=True)
    session.connect(s_get('Open_Requst'))

def fuzzing_IOCTL_Request(session):
    s_initialize(name="IOCTL_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x29]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x27]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=False)
        s_bytes(value=bytes([0x0e, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=False)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x40, 0xff, 0xff,  0x00, 0x00]), size=6, max_len=6, name='Word_parameters',
                fuzzable=False)
        s_bytes(value=bytes([0x0e, 0x00]), size=2, max_len=2, name='Byte_count', fuzzable=False)
    session.connect(s_get('IOCTL_Request'))


def fuzzing_Read_AndX_Request(session):
    s_initialize(name="Read_AndX_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x3b]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x2e]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0xfa, 0x7a]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0xaa, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='andXcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Andxoffset', fuzzable=False)
        s_bytes(value=bytes([0x2a, 0x40]), size=2, max_len=2, name='FID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x80, 0x00, 0x00]), size=4, max_len=4, name='Offset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x80]), size=2, max_len=2, name='Min_count_low', fuzzable=False)
        s_bytes(value=bytes([0xd8, 0x78]), size=2, max_len=2, name='Min_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Max_count_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Remaining', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='High_offset', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
        session.connect(s_get('Read_AndX_Request'))


def fuzzing_Write_AndX_Request(session):
    s_initialize(name="Write_AndX_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x46]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x2f]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x07, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x0e]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='andXcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Andxoffset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x40]), size=2, max_len=2, name='FID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Offset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='reserved2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='write_MOde', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Remaining', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Data_length_high', fuzzable=False)
        s_bytes(value=bytes([0x07, 0x00]), size=2, max_len=2, name='Date_length_low', fuzzable=False)
        s_bytes(value=bytes([0x3f, 0x00]), size=2, max_len=2, name='Date_offset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='high_offset', fuzzable=False)
        s_bytes(value=bytes([0x07, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
        s_bytes(value=bytes([0x61,0x62,0x63,0x00,0x00,0x00,0x00]), size=7, max_len=7, name='File_Date', fuzzable=True)

        session.connect(s_get('Write_AndX_Request'))

def fuzzing_Logoff_AndX_Request(session):
    s_initialize(name="Logoff_AndX_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x27]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component',
                fuzzable=False)
        s_bytes(value=bytes([0x74]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x1e, 0x7a]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x13, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='AndXcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='ReServed', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Andxoffset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
    session.connect(s_get('Logoff_AndX_Request'))

def fuzzing_Locking_AndX_Request(session):
    s_initialize(name="Locking_AndX_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x33]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component',
                fuzzable=False)
        s_bytes(value=bytes([0x24]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='error_class', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=1, max_len=1, name='error_code', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='flag2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0xff, 0xff]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0xff, 0xff]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='andXcommand', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Andxoffset', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x40]), size=2, max_len=2, name='FID', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Lock_Type', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Oplock_Level', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='timeout', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Number_of_unlocks', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Number_of_locks', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
    session.connect(s_get('Locking_AndX_Request'))


def fuzzing_lock_Byte_Range_Request(session):
    s_initialize(name="lock_Byte_Range_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x2d]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component',
                fuzzable=False)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x1f, 0x7a]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x40]), size=2, max_len=2, name='FID', fuzzable=False)
        s_bytes(value=bytes([0xa2, 0x0f, 0x00, 0x00]), size=4, max_len=4, name='COUNT', fuzzable=False)
        s_bytes(value=bytes([0x11, 0x27, 0x00, 0x00]), size=4, max_len=4, name='offset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
    session.connect(s_get('lock_Byte_Range_Request'))



def fuzzing_Unlock_Byte_Range_Request(session):
    s_initialize(name="Unlock_Byte_Range_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x2d]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component',
                fuzzable=False)
        s_bytes(value=bytes([0x0d]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x1f, 0x7a]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x44, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x40]), size=2, max_len=2, name='FID', fuzzable=False)
        s_bytes(value=bytes([0xa2, 0x0f, 0x00, 0x00]), size=4, max_len=4, name='COUNT', fuzzable=False)
        s_bytes(value=bytes([0x11, 0x27, 0x00, 0x00]), size=4, max_len=4, name='offset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
    session.connect(s_get('Unlock_Byte_Range_Request'))





def fuzzing_Query_Information_Disk_Request(session):
    s_initialize(name="Query_Information_Disk_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x23]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x05, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)

        session.connect(s_get("Query_Information_Disk_Request"))


def fuzzing_Find_Request(session):
    s_initialize(name="Find_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x53]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x82]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x0b, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='Mac_count', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Search_Attributes', fuzzable=False)
        s_bytes(value=bytes([0x2c, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes([0x5c,0x00,0x74,0x00,0x6f,0x00,0x72,0x00,0x74,0x00,0x75,0x00,0x72,0x00,0x65,0x00,0x5f,0x00,
                             0x73,0x00,0x65,0x00,0x61,0x00,0x72,0x00,0x63,0x00,0x68,0x00,0x2e,0x00,0x74,0x00,0x78,0x00,0x74,
                             0x00,0x00,0x00]), size=40, max_len=40, name='File_Name', fuzzable=True)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Buffer_format1', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Resume_Key_Length', fuzzable=False)
    session.connect(s_get('Find_Request'))

def fuzzing_Find_Close_Request(session):
    s_initialize(name="Find_Close_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x42]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x84]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x0c, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='Max_count', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Search_Attributes', fuzzable=False)
        s_bytes(value=bytes([0x1b, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='File_Name', fuzzable=True)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Buffer_format1', fuzzable=False)
        s_bytes(value=bytes([0x15, 0x00]), size=2, max_len=2, name='Resume_Key_Length', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x54,0x4f,0x52,0x54,0x55,0x52,0x7e,0x31,0x54,0x58,0x54]), size=11, max_len=11, name='File_name', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Find_ID', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='server_cookie', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='client_cookie', fuzzable=False)
    session.connect(s_get('Find_Close_Request'))

def fuzzing_Find_Unique_Request(session):
    s_initialize(name="Find_Unique_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x53]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x83]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x0e, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='Max_count', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Search_Attributes', fuzzable=False)
        s_bytes(value=bytes([0x2c, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes(
            [0x5c, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00, 0x5f, 0x00,
             0x73, 0x00, 0x65, 0x00, 0x61, 0x00, 0x72, 0x00, 0x63, 0x00, 0x68, 0x00, 0x2e, 0x00, 0x74, 0x00, 0x78, 0x00,
             0x74,0x00, 0x00, 0x00]), size=40, max_len=40, name='File_Name', fuzzable=True)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Buffer_format1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Resume_Key_Length', fuzzable=False)

    session.connect(s_get('Find_Unique_Request'))

def fuzzing_Search_Request(session):
    s_initialize(name="Search_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x53]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x81]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x10, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='Max_count', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Search_Attributes', fuzzable=False)
        s_bytes(value=bytes([0x2c, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes(
            [0x5c, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00, 0x5f,
             0x00,0x73, 0x00, 0x65, 0x00, 0x61, 0x00, 0x72, 0x00, 0x63, 0x00, 0x68, 0x00, 0x2e, 0x00, 0x74, 0x00, 0x78,
             0x00,0x74, 0x00, 0x00, 0x00]), size=40, max_len=40, name='File_Name', fuzzable=True)
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name='Buffer_format1', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Resume_Key_Length', fuzzable=False)

    session.connect(s_get('Search_Request'))


def fuzzing_Trans2_Request(session):
    s_initialize(name="Trans2_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x46]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x32]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x06, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x0f]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x00]), size=2, max_len=2, name='Total_parameter_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Total_data_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='max_parameter_count', fuzzable=False)
        s_bytes(value=bytes([0xff, 0xff]), size=2, max_len=2, name='max_data_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='max_setup_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved3', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='flag3', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='timeout', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='reserved1', fuzzable=False)
        s_bytes(value=bytes([0x02, 0x00]), size=2, max_len=2, name='parameter_count', fuzzable=False)
        s_bytes(value=bytes([0x44, 0x00]), size=2, max_len=2, name='parameter_offset', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='data_count', fuzzable=False)
        s_bytes(value=bytes([0x46, 0x00]), size=2, max_len=2, name='data_offset', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='setup_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='reserved2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='sbucommand', fuzzable=False)
        s_bytes(value=bytes([0x05, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00,0x00]), size=3, max_len=3, name='padding', fuzzable=False)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='Level_of_interest', fuzzable=True)
        session.connect(s_get("Trans2_Request"))

def fuzzing_Set_Information2_Request(session):
    s_initialize(name="Set_Information2_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x31]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x22]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x13, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x40]), size=2, max_len=2, name='FID', fuzzable=True)
        s_bytes(value=bytes([0x10, 0x35]), size=2, max_len=2, name='DOS_date', fuzzable=False)
        s_bytes(value=bytes([0xfd,0x73]), size=2, max_len=2, name='DOS_Time', fuzzable=False)
        s_bytes(value=bytes([0xb2, 0x34]), size=2, max_len=2, name='DOS_date1', fuzzable=False)
        s_bytes(value=bytes([0xfd,0x73]), size=2, max_len=2, name='DOS_Time1', fuzzable=False)
        s_bytes(value=bytes([0x51, 0x34]), size=2, max_len=2, name='DOS_date2', fuzzable=False)
        s_bytes(value=bytes([0xfd, 0x73]), size=2, max_len=2, name='DOS_Time2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Byte_count', fuzzable=False)

    session.connect(s_get('Set_Information2_Request'))

def fuzzing_Query_Information2_Request(session):
    s_initialize(name="Query_Information2_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x25]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x23]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x0a, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x40]), size=2, max_len=2, name='FID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
    session.connect(s_get('Query_Information2_Request'))



def fuzzing_Tran_Disconnect_Request(session):
    s_initialize(name="Tran_Disconnect_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x23]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x71]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x13, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)

        session.connect(s_get("Tran_Disconnect_Request"))



def fuzzing_Rename_Request(session):
    s_initialize(name="Rename_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x80]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0x07]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0xfa, 0x7a]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x09, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Serach_attributes', fuzzable=False)
        s_bytes(value=bytes([0x5b, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes(
            [0x5c, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x61
               ,0x00 , 0x6d,0x00, 0x65,0x00,0x5c,0x00,0x74,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x31,0x00,0x2e,0x00
             ,0x74,0x00,0x78,0x00,0x74,0x00,0x00,0x00]), size=44, max_len=44, name='old_file_Name', fuzzable=False)
        s_bytes(value=bytes([0x04,0x00]), size=2, max_len=2, name='Buffer_format1', fuzzable=False)
        s_bytes(value=bytes(
            [0x5c, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x61
               ,0x00 , 0x6d,0x00, 0x65,0x00,0x5c,0x00,0x74,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x32,0x00,0x2e,0x00
             ,0x74,0x00,0x78,0x00,0x74,0x00,0x00,0x00]), size=44, max_len=44, name='File_Name', fuzzable=False)
        session.connect(s_get("Rename_Request"))



def fuzzing_NT_Rename_Request(session):
    s_initialize(name="NT_Rename_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x86]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component', fuzzable=False)
        s_bytes(value=bytes([0xa5]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8, name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0xfa, 0x7a]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x2a, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Serach_attributes', fuzzable=False)
        s_bytes(value=bytes([0x04, 0x01]), size=2, max_len=2, name='Level_of_Interest', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='Cluster_count', fuzzable=False)
        s_bytes(value=bytes([0x5b, 0x00]), size=2, max_len=2, name='byte_count', fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='Buffer_format', fuzzable=False)
        s_bytes(value=bytes(
            [0x5c, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x61
               ,0x00 , 0x6d,0x00, 0x65,0x00,0x5c,0x00,0x74,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x31,0x00,0x2e,0x00
             ,0x74,0x00,0x78,0x00,0x74,0x00,0x00,0x00]), size=44, max_len=44, name='old_file_Name', fuzzable=False)
        s_bytes(value=bytes([0x04,0x00]), size=2, max_len=2, name='Buffer_format1', fuzzable=False)
        s_bytes(value=bytes(
            [0x5c, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x61
               ,0x00 , 0x6d,0x00, 0x65,0x00,0x5c,0x00,0x74,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x32,0x00,0x2e,0x00
             ,0x74,0x00,0x78,0x00,0x74,0x00,0x00,0x00]), size=44, max_len=44, name='File_Name', fuzzable=False)
        session.connect(s_get("NT_Rename_Request"))






def fuzzing_Close_Request(session):
    s_initialize(name="Close_Request")
    with s_block("NetBIOS_session"):
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Message_Type', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x29]), size=3, max_len=3, name='length', fuzzable=False)
    with s_block("SMB"):
        s_bytes(value=bytes([0xff, 0x53, 0x4d, 0x42]), size=4, max_len=4, name='server_component',
                fuzzable=False)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name='SMB_command', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name='NT_staus', fuzzable=False)
        s_bytes(value=bytes([0x08]), size=1, max_len=1, name='flags', fuzzable=False)
        s_bytes(value=bytes([0x03, 0xc8]), size=2, max_len=2, name='flags2', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Process_ID_High', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), size=8, max_len=8,
                name='Signature',
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='reserved', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='Tree_ID', fuzzable=True)
        s_bytes(value=bytes([0x43, 0x79]), size=2, max_len=2, name='Process_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name='User_ID', fuzzable=True)
        s_bytes(value=bytes([0x46, 0x00]), size=2, max_len=2, name='Multiplex_ID', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Word_count', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x40]), size=2, max_len=2, name='FID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x00]), size=4, max_len=4, name='Last_write', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Byte_Count', fuzzable=False)
    session.connect(s_get('Close_Request'))


if __name__ == "__main__":
    fuzzing_main()