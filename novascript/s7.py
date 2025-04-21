
host_ip = ''
host_port = 102

def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_Setup_Communication(session=session)
    fuzzing_Read_Var(session=session)
    fuzzing_Write_Var(session=session)
    fuzzing_Request_download(session=session)
    fuzzing_Download_ended(session=session)
    fuzzing_Download_ended1(session=session)
    fuzzing_Start_upload(session=session)
    fuzzing_Upload(session=session)
    fuzzing_End_upload(session=session)
    fuzzing_PI_service(session=session)
    fuzzing_PLC_stop(session=session)
    fuzzing_List_blocks(session=session)
    fuzzing_List_blocks_of_type(session=session)
    fuzzing_Get_block_info(session=session)
    fuzzing_Read_SZL(session=session)
    fuzzing_Message_service(session=session)
    fuzzing_PLC_password(session=session)
    session.fuzz()


def fuzzing_Setup_Communication(session):
    # ----------Job---------- #
    # ----------Setup Communication---------- #
    # Function : Setup communication (0xf0)
    s_initialize(name="Setup_Communication")
    with s_block("TPKT"):
        # version 版本信息
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # Reserved 保留 值为0x00
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        # Length TPKT、COTP、S7三层协议的总长度，也就是TCP的payload的长度
        s_bytes(value=bytes([0x00, 0x19]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        # Length COTP后续数据的长度（注意：长度不包含length的长度），一般为2bytes
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        # PDU type 类型
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        # TPDU number
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)

    with s_block("S7 Communication"):
        with s_block("Header"):
            # Protocol Id 协议ID，通常为0x32
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            #
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            # Redundancy Identification(Reserved) 冗余数据，通常为0x0000
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            # Protocol Data Unit Reference. it is increased by request event. 协议数据单元参考，通过请求事件增加
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            # Parameter length the total length(bytes) of parameter part 参数的总长度
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=True)
            # Data length 数据长度 如果读取PLC内部数据，此处为0x0000
            # 对于其他功能，则为Data部分的数据长度
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)

        with s_block("Parameter"):
            # Function PDU的类型 功能码
            s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="function", fuzzable=False)
            # Reserved 冗余数据 通常为0x0000
            # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
            s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
            # Max_AmQ_calling 发送连接请求
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Max_AmQ_calling", fuzzable=False)
            # Max_AmQ_called 发送通信请求
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Max_AmQ_called", fuzzable=False)
            # PDU_length 协商的PDU长度
            s_bytes(value=bytes([0x01, 0xe0]), size=2, max_len=2, name="PDU_length", fuzzable=False)
    session.connect(s_get('Setup_Communication'))

    # ----------Read Var---------- #
    # Function : Read Var (0x04)
def fuzzing_Read_Var(session):
    s_initialize(name="Read Var")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x1f]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0x31, 0x06]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0e]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name="function", fuzzable=False)
            # s_bytes(value=bytes([0x01]), size=1, max_len=1, name="reserved", fuzzable=False)
            s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
            with s_block("Item"):
                s_bytes(value=bytes([0x12]), size=1, max_len=1, name="variable_specification", fuzzable=False)
                s_bytes(value=bytes([0x0a]), size=1, max_len=1, name="address_length", fuzzable=False)
                s_bytes(value=bytes([0x10]), size=1, max_len=1, name="syntax_id", fuzzable=False)
                s_bytes(value=bytes([0x02]), size=1, max_len=1, name="transport_size", fuzzable=False)
                s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="length", fuzzable=False)
                s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="dn_number", fuzzable=False)
                s_bytes(value=bytes([0x81]), size=1, max_len=1, name="area", fuzzable=False)
                s_bytes(value=bytes([0x00, 0x00, 0x00]), size=3, max_len=3, name="address", fuzzable=False)
    session.connect(s_get('Read Var'))
        
    

    # ----------Write Var---------- #
    # Function : Write Var (0x05)
def fuzzing_Write_Var(session):
    s_initialize(name="Write_Var")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x27]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0x18, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0e]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x05]), size=1, max_len=1, name="function", fuzzable=False)
            # s_bytes(value=bytes([0x01]), size=1, max_len=1, name="reserved", fuzzable=False)
            s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
            with s_block("Item"):
                s_bytes(value=bytes([0x12]), size=1, max_len=1, name="variable_specification", fuzzable=False)
                s_bytes(value=bytes([0x0a]), size=1, max_len=1, name="address_length", fuzzable=False)
                s_bytes(value=bytes([0x10]), size=1, max_len=1, name="syntax_id", fuzzable=False)
                s_bytes(value=bytes([0x08]), size=1, max_len=1, name="transport_size", fuzzable=False)
                s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="length", fuzzable=False)
                s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="dn_number", fuzzable=False)
                s_bytes(value=bytes([0x83]), size=1, max_len=1, name="area", fuzzable=False)
                s_bytes(value=bytes([0x00, 0x00, 0x80]), size=3, max_len=3, name="address", fuzzable=False)
            
        
        with s_block("Data"):
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="return_code", fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name="transport_size", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name="length", fuzzable=False)
            s_bytes(value=bytes([0x79, 0xe9, 0xf6, 0x42]), size=4, max_len=4, name="data", fuzzable=False)
    session.connect(s_get('Write_Var'))
    

    # ----------Request download---------- #
    # Function : Request download (0x1a)
def fuzzing_Request_download(session):
    s_initialize(name="Request_download")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x31]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0x77, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x20]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x1a]), size=1, max_len=1, name="function", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="function status", fuzzable=False)
            s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name="unknown byte 1", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name="unknown byte 2", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="filename length", fuzzable=False)
            with s_block("Filename"):
                s_bytes(value=bytes([0x5f]), size=1, max_len=1, name="file id", fuzzable=False)
                s_bytes(value=bytes([0x30, 0x42]), size=2, max_len=2, name="block type", fuzzable=False)
                s_bytes(value=bytes([0x30, 0x30, 0x30, 0x30, 0x37]), size=5, max_len=5, name="block number",
                        fuzzable=False)
                s_bytes(value=bytes([0x50]), size=1, max_len=1, name="destination filesystem", fuzzable=False)
            
            s_bytes(value=bytes([0x0d]), size=1, max_len=1, name="length part", fuzzable=False)
            s_bytes(value=bytes([0x31]), size=1, max_len=1, name="unknown char before load mem", fuzzable=False)
            s_bytes(value=bytes([0x30, 0x30, 0x30, 0x30, 0x39, 0x34]), size=6, max_len=6, name="length of load memory",
                    fuzzable=False)
            s_bytes(value=bytes([0x30, 0x30, 0x30, 0x30, 0x39, 0x34]), size=6, max_len=6, name="length of MC7 code",
                    fuzzable=False)
    session.connect(s_get('Request_download'))
    

    # ----------Download_ended---------- #
    # Function : Download_ended (0x1b)
def fuzzing_Download_ended(session):
    s_initialize(name="Download_ended")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x23]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0xc1, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x12]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x1b]), size=1, max_len=1, name="function", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="function status", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="unknown byte 1", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name="unknown byte 2", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="filename length", fuzzable=False)
            with s_block("Filename"):
                s_bytes(value=bytes([0x5f]), size=1, max_len=1, name="file id", fuzzable=False)
                s_bytes(value=bytes([0x30, 0x42]), size=2, max_len=2, name="block type", fuzzable=False)
                s_bytes(value=bytes([0x30, 0x30, 0x30, 0x30, 0x37]), size=5, max_len=5, name="block number",
                        fuzzable=False)
                s_bytes(value=bytes([0x50]), size=1, max_len=1, name="destination filesystem", fuzzable=False)
    session.connect(s_get('Download_ended'))
        
    

    # ----------Download ended---------- #
    # Function : Download ended
def fuzzing_Download_ended1(session):
    s_initialize(name="Download_ended1")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x23]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0xc3, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x12]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x1c]), size=1, max_len=1, name="function", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="function status", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="unknown byte 1", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name="unknown byte 2", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="filename length", fuzzable=False)
            with s_block("Filename"):
                s_bytes(value=bytes([0x5f]), size=1, max_len=1, name="file id", fuzzable=False)
                s_bytes(value=bytes([0x30, 0x42]), size=2, max_len=2, name="block type", fuzzable=False)
                s_bytes(value=bytes([0x30, 0x30, 0x30, 0x30, 0x37]), size=5, max_len=5, name="block number",
                        fuzzable=False)
                s_bytes(value=bytes([0x50]), size=1, max_len=1, name="destination filesystem", fuzzable=False)
    session.connect(s_get('Download_ended1'))
        
    

    # ----------Start upload---------- #
    # Function : Start upload (0x1d)
def fuzzing_Start_upload(session):
    s_initialize(name="Start_upload")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x23]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            # Protocol Data Unit Reference
            s_bytes(value=bytes([0x08, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x12]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x1d]), size=1, max_len=1, name="function", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="function status", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="unknown", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00]), size=4, max_len=4, name="upload id", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="filename length", fuzzable=False)
            with s_block("Filename"):
                s_bytes(value=bytes([0x5f]), size=1, max_len=1, name="file id", fuzzable=False)
                # Block type
                s_bytes(value=bytes([0x30, 0x42]), size=2, max_len=2, name="block type", fuzzable=False)
                s_bytes(value=bytes([0x30, 0x30, 0x30, 0x30, 0x30]), size=5, max_len=5, name="block number",
                        fuzzable=False)
                s_bytes(value=bytes([0x41]), size=1, max_len=1, name="destination filesystem", fuzzable=False)
    session.connect(s_get('Start_upload'))
        
    

    # ----------Upload---------- #
    # Function : Upload (0x1e)
def fuzzing_Upload(session):
    s_initialize(name="Upload")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x19]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            # Protocol Data Unit Reference
            s_bytes(value=bytes([0x09, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            # Function
            s_bytes(value=bytes([0x1e]), size=1, max_len=1, name="function", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="function status", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="unknown", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x07]), size=4, max_len=4, name="upload id", fuzzable=False)
    session.connect(s_get('Upload'))
    

    # ----------End upload---------- #
    # Function : End upload (0x1e)
def fuzzing_End_upload(session):
    s_initialize(name="End_upload")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x19]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            # Protocol Data Unit Reference
            s_bytes(value=bytes([0x0a, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            # Function
            s_bytes(value=bytes([0x1f]), size=1, max_len=1, name="function", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="function status", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="unknown", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x07]), size=4, max_len=4, name="upload id", fuzzable=False)
    session.connect(s_get('End_upload'))
    

    # ----------PI service---------- #
    # Function : PI service (0x28)
def fuzzing_PI_service(session):
    s_initialize(name="PI_service")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x23]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            # Protocol Data Unit Reference
            s_bytes(value=bytes([0x1d, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x12]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            # Function
            s_bytes(value=bytes([0x28]), size=1, max_len=1, name="function", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd]), size=7, max_len=7, name="unknown bytes",
                    fuzzable=False)
            s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name="parameter block length", fuzzable=False)
            s_bytes(value=bytes([0x45, 0x50]), size=2, max_len=2, name="parameter block", fuzzable=False)
            s_bytes(value=bytes([0x05]), size=1, max_len=1, name="string length", fuzzable=False)
            s_bytes(value=bytes([0x5f, 0x4d, 0x4f, 0x44, 0x55]), size=5, max_len=5, name="PI program invocation",
                    fuzzable=False)
    session.connect(s_get('PI_service'))
    

    # ----------PLC stop---------- #
    # Function : PLC stop (0x29)
def fuzzing_PLC_stop(session):
    s_initialize(name="PLC_stop")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x21]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            # Protocol Data Unit Reference
            s_bytes(value=bytes([0x1c, 0x02]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x10]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            # Function
            s_bytes(value=bytes([0x29]), size=1, max_len=1, name="function", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00, 0x00, 0x00, 0x00]), size=5, max_len=5, name="unknown bytes",
                    fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="length part", fuzzable=False)
            s_bytes(value=bytes([0x50, 0x5f, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d]), size=9, max_len=9,
                    name="upload id", fuzzable=False)
        session.connect(s_get('PLC_stop'))
    

    # ----------UserData---------- #
    # ----------List blocks----------#
    # Subfunction : List blocks (0x01)
    # payload [5:7] : 0x43 0x01 Req
    # payload [5:7] : 0x83 0x01 Rsp
def fuzzing_List_blocks(session):
    s_initialize(name="List_blocks")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x1d]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0x04, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x00, 0x01, 0x12]), size=3, max_len=3, name="parameter head", fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name="parameter length", fuzzable=False)
            s_bytes(value=bytes([0x11]), size=1, max_len=1, name="method", fuzzable=False)
            s_bytes(value=bytes([0x43]), size=1, max_len=1, name="type", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="subfunction", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="sequence number", fuzzable=False)
        
        with s_block("Data"):
            s_bytes(value=bytes([0x0a]), size=1, max_len=1, name="return_code", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="transport_size", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="length", fuzzable=False)

    session.connect(s_get('List_blocks'))

    # ----------List blocks of type----------#
    # Subfunction : List blocks of type (0x02)
    # payload [5:7] : 0x43 0x02 Req
    # payload [5:7] : 0x83 0x02 Rsp
def fuzzing_List_blocks_of_type(session):
    s_initialize(name="List_blocks_of_type")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x1f]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            # Protocol Data Unit Reference
            s_bytes(value=bytes([0x05, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x00, 0x01, 0x12]), size=3, max_len=3, name="parameter head", fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name="parameter length", fuzzable=False)
            s_bytes(value=bytes([0x11]), size=1, max_len=1, name="method", fuzzable=False)
            s_bytes(value=bytes([0x43]), size=1, max_len=1, name="type", fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name="subfunction", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="sequence number", fuzzable=False)
        
        with s_block("Data"):
            s_bytes(value=bytes([0xff]), size=1, max_len=1, name="return_code", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="transport_size", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name="length", fuzzable=False)
            # Block type
            s_bytes(value=bytes([0x30, 0x44]), size=2, max_len=2, name="block type", fuzzable=False)
    session.connect(s_get('List_blocks_of_type'))
    

    # ----------Get block info----------#
    # Subfunction : Get block info (0x03)
    # payload [5:7] : 0x43 0x03 Req
    # payload [5:7] : 0x83 0x03 Rsp
def fuzzing_Get_block_info(session):
    s_initialize(name="Get_block_info")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x25]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            # Protocol Data Unit Reference
            s_bytes(value=bytes([0x11, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0c]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x00, 0x01, 0x12]), size=3, max_len=3, name="parameter head", fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name="parameter length", fuzzable=False)
            s_bytes(value=bytes([0x11]), size=1, max_len=1, name="method", fuzzable=False)
            s_bytes(value=bytes([0x43]), size=1, max_len=1, name="type", fuzzable=False)
            s_bytes(value=bytes([0x03]), size=1, max_len=1, name="subfunction", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="sequence number", fuzzable=False)
        
        with s_block("Data"):
            s_bytes(value=bytes([0xff]), size=1, max_len=1, name="return_code", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="transport_size", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="length", fuzzable=False)
            # Block type
            s_bytes(value=bytes([0x30, 0x44]), size=2, max_len=2, name="block type", fuzzable=False)
            s_bytes(value=bytes([0x30, 0x30, 0x30, 0x30, 0x30]), size=5, max_len=5, name="block number", fuzzable=False)
            s_bytes(value=bytes([0x42]), size=1, max_len=1, name="Filesystem", fuzzable=False)
    session.connect(s_get('Get_block_info'))
    

    # ----------Read SZL----------#
    # Subfunction : Read SZL (0x01)
    # payload [5:7] : 0x44 0x01 Req
    # payload [5:7] : 0x84 0x01 Rsp
def fuzzing_Read_SZL(session):
    s_initialize(name="Read_SZL")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x21]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0x03, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x00, 0x01, 0x12]), size=3, max_len=3, name="parameter head", fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name="parameter length", fuzzable=False)
            s_bytes(value=bytes([0x11]), size=1, max_len=1, name="method", fuzzable=False)
            s_bytes(value=bytes([0x44]), size=1, max_len=1, name="type", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="subfunction", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="sequence number", fuzzable=False)
        
        with s_block("Data"):
            s_bytes(value=bytes([0xff]), size=1, max_len=1, name="return_code", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="transport_size", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name="length", fuzzable=False)
            s_bytes(value=bytes([0x01, 0x32, 0x00, 0x04]), size=4, max_len=4, name="data", fuzzable=False)
    session.connect(s_get('Read_SZL'))
    

    # ----------Message service----------#
    # Subfunction : Message service (0x02)
    # payload [5:7] : 0x44 0x02 Req
    # payload [5:7] : 0x84 0x02 Rsp
def fuzzing_Message_service(session):
    s_initialize(name="Message_service")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x27]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0x0f, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0e]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x00, 0x01, 0x12]), size=3, max_len=3, name="parameter head", fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name="parameter length", fuzzable=False)
            s_bytes(value=bytes([0x11]), size=1, max_len=1, name="method", fuzzable=False)
            s_bytes(value=bytes([0x44]), size=1, max_len=1, name="type", fuzzable=False)
            s_bytes(value=bytes([0x02]), size=1, max_len=1, name="subfunction", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="sequence number", fuzzable=False)
        
        with s_block("Data"):
            s_bytes(value=bytes([0xff]), size=1, max_len=1, name="return_code", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="transport_size", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="length", fuzzable=False)
            s_bytes(value=bytes([0x03]), size=1, max_len=1, name="subscribed events", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved/unknown", fuzzable=False)
            s_bytes(value=bytes([0x61, 0x73, 0x6d, 0x65, 0x73, 0x73, 0x00, 0x00]), size=8, max_len=8, name="Username",
                    fuzzable=False)
    session.connect(s_get('Message_service'))
    

    # ----------PLC password----------#
    # Subfunction : PLC password (0x01)
    # payload [5:7] : 0x45 0x01 Req
    # payload [5:7] : 0x85 0x01 Rsp
def fuzzing_PLC_password(session):
    s_initialize(name="PLC_password")
    with s_block("TPKT"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="version", fuzzable=False)
        # s_bytes(value=bytes([0x00]), size=1, max_len=1, name="reserved", fuzzable=False)
        s_random(value=bytes([0x00]), min_length=1, max_length=1, num_mutations=10, name="reserved")
        s_bytes(value=bytes([0x00, 0x25]), size=2, max_len=2, name="length", fuzzable=False)
    
    with s_block("COTP"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="length", fuzzable=False)
        s_bytes(value=bytes([0xf0]), size=1, max_len=1, name="PDU_Type", fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name="TPDU_number", fuzzable=False)
    
    with s_block("S7 Communication"):
        with s_block("Header"):
            s_bytes(value=bytes([0x32]), size=1, max_len=1, name="protocol_id", fuzzable=False)
            s_bytes(value=bytes([0x07]), size=1, max_len=1, name="ROSCTR", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="redundancy_id", fuzzable=False)
            s_bytes(value=bytes([0x06, 0x00]), size=2, max_len=2, name="protocol_data", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="parameter_length", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x0c]), size=2, max_len=2, name="data_length", fuzzable=False)
        
        with s_block("Parameter"):
            s_bytes(value=bytes([0x00, 0x01, 0x12]), size=3, max_len=3, name="parameter head", fuzzable=False)
            s_bytes(value=bytes([0x04]), size=1, max_len=1, name="parameter length", fuzzable=False)
            s_bytes(value=bytes([0x11]), size=1, max_len=1, name="method", fuzzable=False)
            s_bytes(value=bytes([0x45]), size=1, max_len=1, name="type", fuzzable=False)
            s_bytes(value=bytes([0x01]), size=1, max_len=1, name="subfunction", fuzzable=False)
            s_bytes(value=bytes([0x00]), size=1, max_len=1, name="sequence number", fuzzable=False)
        
        with s_block("Data"):
            s_bytes(value=bytes([0xff]), size=1, max_len=1, name="return_code", fuzzable=False)
            s_bytes(value=bytes([0x09]), size=1, max_len=1, name="transport_size", fuzzable=False)
            s_bytes(value=bytes([0x00, 0x08]), size=2, max_len=2, name="length", fuzzable=False)
            s_bytes(value=bytes([0x21, 0x3a, 0x1b, 0x1d, 0x6e, 0x68, 0x1b, 0x1d]), size=8, max_len=8, name="data",
                    fuzzable=False)
    session.connect(s_get('PLC_password'))
    






if __name__ == "__main__":
    fuzzing_main()
