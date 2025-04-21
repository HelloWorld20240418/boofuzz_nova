
host_ip = ''
host_port = 9600

def fuzzing_main():
    session = Session(target=Target(connection=UDPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_Command_Run(session=session)
    fuzzing_Command_memory_area_read(session=session)
    fuzzing_Command_memory_area_Write(session=session)
    fuzzing_Command_memory_area_Fill(session=session)
    fuzzing_Command_Multiple_memory_area_Read(session=session)
    fuzzing_Command_memory_area_Transfer(session=session)
    fuzzing_Command_Parameter_area_read(session=session)
    fuzzing_Command_Parameter_area_Wirte(session=session)
    fuzzing_Command_Data_link_table_read(session=session)
    fuzzing_Command_Data_link_table_Wirte(session=session)
    fuzzing_Command_Parameter_Area_Clear(session=session)
    fuzzing_Command_Program_Area_Protect(session=session)
    fuzzing_Command_Program_Area_Protect_Clear(session=session)
    fuzzing_Command_Program_area_read(session=session)
    fuzzing_Command_Program_area_Write(session=session)
    fuzzing_Command_Program_area_Clear(session=session)
    fuzzing_Command_Controller_data_read(session=session)
    fuzzing_Command_Connection_Data_Read(session=session)
    fuzzing_Command_Controller_Staus_Read(session=session)
    fuzzing_Command_Data_Link_Status_Read(session=session)
    fuzzing_Command_Cycle_Time_Read(session=session)
    fuzzing_Command_Clock_Read(session=session)
    fuzzing_Command_Clock_Write(session=session)
    fuzzing_Command_lOOP_Back_TEST(session=session)
    fuzzing_Command_Broadcast_Test_Results_Read(session=session)
    fuzzing_Command_Broadcast_Test_Data_Send(session=session)
    fuzzing_Command_Message_Read_Message_Clear_FAL_FALS_Read(session=session)
    fuzzing_Command_Access_Right_Acquire(session=session)
    fuzzing_Command_Access_Right_Forced_Acquire(session=session)
    fuzzing_Command_Access_Right_Release(session=session)
    fuzzing_Command_Error_Clear(session=session)
    fuzzing_Command_Error_Log_Read(session=session)
    fuzzing_Command_Error_Log_Clear(session=session)
    fuzzing_Command_File_Name_Read(session=session)
    fuzzing_Command_Single_File_Read(session=session)
    fuzzing_Command_Single_File_Wirte(session=session)
    fuzzing_Command_Memory_Card_format(session=session)
    fuzzing_Command_File_Delete(session=session)
    fuzzing_Command_Volum_Label_Create_Delete(session=session)
    fuzzing_Command_File_Copy(session=session)
    fuzzing_Command_File_Name_Change(session=session)
    fuzzing_Command_File_Data_Check(session=session)
    fuzzing_Command_Memory_Area_File_Transfer(session=session)
    fuzzing_Command_Parameter_Area_File_Transfer(session=session)
    fuzzing_Command_Program_Area_File_Transfer(session=session)
    fuzzing_Command_File_Memory_Index_Read(session=session)
    fuzzing_Command_File_Memory_Read(session=session)
    fuzzing_Command_File_Memory_Write(session=session)
    fuzzing_Command_Forced_set_Reset(session=session)
    fuzzing_Command_Force_set_Reset_Cancel(session=session)
    fuzzing_Command_Multiple_Forced_Status_Read(session=session)
    fuzzing_Command_Name_Set(session=session)
    fuzzing_Command_Name_Delete(session=session)
    fuzzing_Command_Name_Read(session=session)
    fuzzing_Command_Stop(session=session)
    session.fuzz()

        #内存区域读取
def fuzzing_Command_memory_area_read(session):
    s_initialize(name="Command_memory_area_read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x01,0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Memory_Area_code', fuzzable=True)
        s_bytes(value=bytes([0xcc,0xcc]), size=2, max_len=2, name='Beginning_address', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='Beginning_address_bits', fuzzable=True)
        s_bytes(value=bytes([0x00,0x01]), size=1, max_len=1, name='number_of_items', fuzzable=True)
    session.connect(s_get('Command_memory_area_read'))

        #内存区域写入
def fuzzing_Command_memory_area_Write(session):
    s_initialize(name="Command_memory_area_Write")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Memory_Area_code', fuzzable=True)
        s_bytes(value=bytes([0xcc, 0xcc]), size=2, max_len=2, name='Beginning_address', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='Beginning_address_bits', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=1, max_len=1, name='number_of_items', fuzzable=True)
        s_bytes(value=bytes([0x41, 0x42,0x43,0x44,0x45,0x46]), size=6, max_len=6, name='Command_data', fuzzable=True)
    session.connect(s_get('Command_memory_area_Write'))


        #内存区域填充
def fuzzing_Command_memory_area_Fill(session):
    s_initialize(name="Command_memory_area_Fill")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x03]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Memory_Area_code', fuzzable=True)
        s_bytes(value=bytes([0xcc, 0xcc]), size=2, max_len=2, name='Beginning_address', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='Beginning_address_bits', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=1, max_len=1, name='number_of_items', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Command_data',fuzzable=True)
    session.connect(s_get('Command_memory_area_Fill'))

            #多内存区域读取
def fuzzing_Command_Multiple_memory_area_Read(session):
    s_initialize(name="Command_Multiple_memory_area_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x04]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Memory_Area_code', fuzzable=True)
        s_bytes(value=bytes([0xff, 0xff]), size=2, max_len=2, name='Beginning_address', fuzzable=True)
        s_bytes(value=bytes([0xff]), size=1, max_len=1, name='Beginning_address_bits', fuzzable=True)
    session.connect(s_get('Command_Multiple_memory_area_Read'))


            #内存区域传输
def fuzzing_Command_memory_area_Transfer(session):
    s_initialize(name="Command_memory_area_Transfer")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x01,0x05]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Memory_Area_code', fuzzable=True)
        s_bytes(value=bytes([0xcc,0xcc]), size=2, max_len=2, name='Beginning_address', fuzzable=True)
        s_bytes(value=bytes([0x0c]), size=1, max_len=1, name='Beginning_address_bits', fuzzable=True)
        s_bytes(value=bytes([0x81]), size=1, max_len=1, name='Memory_Area_code1', fuzzable=True)
        s_bytes(value=bytes([0xcc, 0xcd]), size=2, max_len=2, name='Beginning_address1', fuzzable=True)
        s_bytes(value=bytes([0xce]), size=1, max_len=1, name='Beginning_address_bits1', fuzzable=True)
        s_bytes(value=bytes([0x00,0x10]), size=1, max_len=1, name='number_of_items', fuzzable=True)
    session.connect(s_get('Command_memory_area_Transfer'))


        #参数区域读取
def fuzzing_Command_Parameter_area_read(session):
    s_initialize(name="Command_Parameter_area_read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x80,0x10]), size=1, max_len=1, name='Parameter_Area_code', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Beginning_word', fuzzable=True)
        s_bytes(value=bytes([0x00, 0xff]), size=2, max_len=2, name='NO.word_or_bytes', fuzzable=True)
    session.connect(s_get('Command_Parameter_area_read'))

        #参数区域写入
def fuzzing_Command_Parameter_area_Wirte(session):
    s_initialize(name="Command_Parameter_area_Wirte")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x80,0x10]), size=1, max_len=1, name='Parameter_Area_code', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Beginning_word', fuzzable=True)
        s_bytes(value=bytes([0x00, 0xff]), size=2, max_len=2, name='NO.word_or_bytes', fuzzable=True)
        s_bytes(value=bytes([0x44, 0x41,0x54,0x41]), size=2, max_len=2, name='Command_Data', fuzzable=True)
    session.connect(s_get('Command_Parameter_area_Wirte'))


        #数据链表读取
def fuzzing_Command_Data_link_table_read(session):
    s_initialize(name="Command_Data_link_table_read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x02,0x20]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='FIXed', fuzzable=True)
        s_bytes(value=bytes([0x53,0x4e]), size=2, max_len=2, name='Intelligent_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='First_word', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Read_length', fuzzable=True)
    session.connect(s_get('Command_Data_link_table_read'))


            #内存区域传输
def fuzzing_Command_Data_link_table_Wirte(session):
    s_initialize(name="Command_Data_link_table_Wirte")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x02, 0x21]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='FIXed', fuzzable=True)
        s_bytes(value=bytes([0x53, 0x4e]), size=2, max_len=2, name='Intelligent_ID', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='First_word', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Read_length', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='NO_of_link_nodes', fuzzable=True)
        s_bytes(value=bytes([0x0a, 0x00,0x01,0x00,0x00,0x01,0x00,0x02]), size=8, max_len=8, name='block_record1', fuzzable=True)
        s_bytes(value=bytes([0x0a, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02]), size=8, max_len=8, name='block_record2',fuzzable=True)
    session.connect(s_get('Command_Data_link_table_Wirte'))


        #参数区域清除
def fuzzing_Command_Parameter_Area_Clear(session):
    s_initialize(name="Command_Parameter_Area_Clear")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x02,0x03]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x80,0x10]), size=2, max_len=2, name='Parameter_area_code', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Begining_word', fuzzable=True)
        s_bytes(value=bytes([0x00, 0xff]), size=2, max_len=2, name='NO._word_or_bytes', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Command_data', fuzzable=True)
    session.connect(s_get('Command_Parameter_Area_Clear'))


            #程序区保护
def fuzzing_Command_Program_Area_Protect(session):
    s_initialize(name="Command_Program_Area_Protect")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x03,0x04]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Protect_code', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Begining_word', fuzzable=True)
        s_bytes(value=bytes([0xff,0xff,0xff, 0xff]), size=4, max_len=4, name='Last_word', fuzzable=True)
        s_bytes(value=bytes([0x50,0x41,0x53,0x53]), size=4, max_len=4, name='Password', fuzzable=True)
    session.connect(s_get('Command_Program_Area_Protect'))

            #程序区保护清除
def fuzzing_Command_Program_Area_Protect_Clear(session):
    s_initialize(name="Command_Program_Area_Protect_Clear")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x03,0x05]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Protect_code', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x00,0x00]), size=4, max_len=4, name='Begining_word', fuzzable=True)
        s_bytes(value=bytes([0xff,0xff,0xff, 0xff]), size=4, max_len=4, name='Last_word', fuzzable=True)
        s_bytes(value=bytes([0x50,0x41,0x53,0x53]), size=4, max_len=4, name='Password', fuzzable=True)
    session.connect(s_get('Command_Program_Area_Protect_Clear'))

            #程序区读取
def fuzzing_Command_Program_area_read(session):
    s_initialize(name="Command_Program_area_read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x03,0x06]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
        s_bytes(value=bytes([0xff,0xff,0xff, 0xff]), size=4, max_len=4, name='Begining_word', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='NO._word_or_bytes', fuzzable=True)
    session.connect(s_get('Command_Program_area_read'))


            #程序区写入
def fuzzing_Command_Program_area_Write(session):
    s_initialize(name="Command_Program_area_Write")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x03,0x07]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
        s_bytes(value=bytes([0xff,0xff,0xff, 0xff]), size=4, max_len=4, name='Begining_word', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x00]), size=2, max_len=2, name='NO._word_or_bytes', fuzzable=True)
        s_bytes(value=bytes([0x41, 0x42, 0x43, 0x44]), size=4, max_len=4, name='Command_Data', fuzzable=True)
    session.connect(s_get('Command_Program_area_Write'))


            #程序区清除
def fuzzing_Command_Program_area_Clear(session):
    s_initialize(name="Command_Program_area_Clear")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x03, 0x08]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Clear_code', fuzzable=True)
    session.connect(s_get('Command_Program_area_Clear'))

            #执行
def fuzzing_Command_Run(session):
    s_initialize(name="Command_Command_Run")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x04, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Mode_code', fuzzable=True)
    session.connect(s_get('Command_Command_Run'))


            #停止
def fuzzing_Command_Stop(session):
    s_initialize(name="Command_Stop")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x04, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
    session.connect(s_get('Command_Stop'))

        #控制器数据读取
def fuzzing_Command_Controller_data_read(session):
    s_initialize(name="Command_Controller_data_read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x05, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=6, max_len=6, name='Command_data', fuzzable=True)
    session.connect(s_get('Command_Controller_data_read'))


        #连接数据读取
def fuzzing_Command_Connection_Data_Read(session):
    s_initialize(name="Command_Connection_Data_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x05, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x01]), size=6, max_len=6, name='unit_address', fuzzable=True)
    session.connect(s_get('Command_Connection_Data_Read'))


        #控制器状态读取
def fuzzing_Command_Controller_Staus_Read(session):
    s_initialize(name="Command_Controller_Staus_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x06, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
    session.connect(s_get('Command_Controller_Staus_Read'))


        #数据连接状态读取
def fuzzing_Command_Data_Link_Status_Read(session):
    s_initialize(name="Command_Data_Link_Status_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x06, 0x03]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
    session.connect(s_get('Command_Data_Link_Status_Read'))

            #循环次数读取
def fuzzing_Command_Cycle_Time_Read(session):
    s_initialize(name="Command_Cycle_Time_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x06, 0x20]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Parameter', fuzzable=True)
    session.connect(s_get('Command_Cycle_Time_Read'))


        #时钟读取
def fuzzing_Command_Clock_Read(session):
    s_initialize(name="Command_Clock_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x07, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
    session.connect(s_get('Command_Clock_Read'))


            #时钟写入
def fuzzing_Command_Clock_Write(session):
    s_initialize(name="Command_Clock_Write")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x07, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x09]), size=1, max_len=1, name='Year', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Month', fuzzable=True)
        s_bytes(value=bytes([0x20]), size=1, max_len=1, name='Date', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Hour', fuzzable=True)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Minute', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Second', fuzzable=True)
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name='Day', fuzzable=True)
    session.connect(s_get('Command_Clock_Write'))

        #环路测试/内部节点响应测试
def fuzzing_Command_lOOP_Back_TEST(session):
    s_initialize(name="Command_lOOP_Back_TEST")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x08, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61
                             ,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,
                             0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61
                             ,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61
                             ,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61
                             ,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61
                             ,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61
                             ,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61
                             ,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,
                             0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61]), size=100, max_len=100, name='Data', fuzzable=True)

    session.connect(s_get('Command_lOOP_Back_TEST'))

        #广播测试/结果读取
def fuzzing_Command_Broadcast_Test_Results_Read(session):
    s_initialize(name="Command_Broadcast_Test_Results_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x08, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)

    session.connect(s_get('Command_Broadcast_Test_Results_Read'))


        #广播测试数据发送
def fuzzing_Command_Broadcast_Test_Data_Send(session):
    s_initialize(name="Command_Broadcast_Test_Data_Send")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x08, 0x03]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
                                , 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                             0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
                                , 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
                                , 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
                                , 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
                                , 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
                                , 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
                                , 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                             0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61]), size=100, max_len=100,
                name='Data', fuzzable=True)
    session.connect(s_get('Command_Broadcast_Test_Data_Send'))

        #消息读取
def fuzzing_Command_Message_Read_Message_Clear_FAL_FALS_Read(session):
    s_initialize(name="Command_Message_Read_Message_Clear_FAL_FALS_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x09, 0x20]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0xff]), size=2, max_len=2, name='Message', fuzzable=True)
    session.connect(s_get('Command_Message_Read_Message_Clear_FAL_FALS_Read'))


        #访问权限获取
def fuzzing_Command_Access_Right_Acquire(session):
    s_initialize(name="Command_Access_Right_Acquire")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x0C, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
    session.connect(s_get('Command_Access_Right_Acquire'))


            #访问权限强制获取
def fuzzing_Command_Access_Right_Forced_Acquire(session):
    s_initialize(name="Command_Access_Right_Forced_Acquire")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x0C, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
    session.connect(s_get('Command_Access_Right_Forced_Acquire'))


            #访问权限释放
def fuzzing_Command_Access_Right_Release(session):
    s_initialize(name="Command_Access_Right_Release")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x0C, 0x03]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
    session.connect(s_get('Command_Access_Right_Release'))

        #错误清除
def fuzzing_Command_Error_Clear(session):
    s_initialize(name="Command_Error_Clear")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x21, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0xff, 0xfe]), size=2, max_len=2, name='Error_reset_FAL_no', fuzzable=True)
    session.connect(s_get('Command_Error_Clear'))

        #错误日志读取
def fuzzing_Command_Error_Log_Read(session):
    s_initialize(name="Command_Error_Log_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x21, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Beginning_record_no', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='no_of_records', fuzzable=True)
    session.connect(s_get('Command_Error_Log_Read'))

        #错误日志清除
def fuzzing_Command_Error_Log_Clear(session):
    s_initialize(name="Command_Error_Log_Clear")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x21, 0x03]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
    session.connect(s_get('Command_Error_Log_Clear'))

        #文件名读取
def fuzzing_Command_File_Name_Read(session):
    s_initialize(name="Command_File_Name_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Beginning_file_position', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='no_of_files', fuzzable=True)
    session.connect(s_get('Command_File_Name_Read'))

        #单文件读取
def fuzzing_Command_Single_File_Read(session):
    s_initialize(name="Command_Single_File_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69,0x6c,0x65,0x6e,0x61,0x6d,0x65,0x2e,0x65,0x78,0x65]), size=12, max_len=12, name='filename', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x00]), size=4, max_len=4, name='file_position', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x20]), size=2, max_len=2, name='Data_length', fuzzable=True)
    session.connect(s_get('Command_Single_File_Read'))

        #单文件写入
def fuzzing_Command_Single_File_Wirte(session):
    s_initialize(name="Command_Single_File_Wirte")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x03]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name='Parameter_code', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69,0x6c,0x65,0x6e,0x61,0x6d,0x65,0x2e,0x65,0x78,0x65]), size=12, max_len=12, name='filename', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00,0x00]), size=4, max_len=4, name='file_position', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x20]), size=2, max_len=2, name='Data_length', fuzzable=True)
        s_bytes(value=bytes([0x61, 0x61,0x61,0x61,0x61,0x61,0x61,0x61,
                             0x61, 0x61,0x61,0x61,0x61,0x61,0x61,0x61,
                             0x61, 0x61,0x61,0x61,0x61,0x61,0x61,0x61,
                             0x61, 0x61,0x61,0x61,0x61,0x61,0x61,0x61]), size=32, max_len=32, name='File_Data', fuzzable=True)
    session.connect(s_get('Command_Single_File_Wirte'))


        #记忆卡格式化
def fuzzing_Command_Memory_Card_format(session):
    s_initialize(name="Command_Memory_Card_format")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x04]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
    session.connect(s_get('Command_Memory_Card_format'))

        #文件删除
def fuzzing_Command_File_Delete(session):
    s_initialize(name="Command_File_Delete")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x05]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name='no_of_files', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69,0x6c,0x65,0x6e,0x61,0x6d,0x65,0x2e,0x65,0x78,0x65]), size=12, max_len=12, name='filename', fuzzable=True)
    session.connect(s_get('Command_File_Delete'))



        #卷标创建/删除
def fuzzing_Command_Volum_Label_Create_Delete(session):
    s_initialize(name="Command_Volum_Label_Create_Delete")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x06]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Volum_parameter_code', fuzzable=True)
        s_bytes(value=bytes([0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x30, 0x31, 0x2e, 0x6c, 0x62, 0x6c]), size=12,
                max_len=12, name='Volume_label', fuzzable=True)
    session.connect(s_get('Command_Volum_Label_Create_Delete'))


        #文件复制
def fuzzing_Command_File_Copy(session):
    s_initialize(name="Command_File_Copy")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x07]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x65, 0x78, 0x65]), size=12,
                max_len=12, name='filename', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no1', fuzzable=True)
        s_bytes(value=bytes([0x6c, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x64, 0x73, 0x64]), size=12,
                max_len=12, name='filename1', fuzzable=True)
    session.connect(s_get('Command_File_Copy'))


        #文件名更改
def fuzzing_Command_File_Name_Change(session):
    s_initialize(name="Command_File_Name_Change")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x08]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x6e, 0x65, 0x77]), size=12,
                max_len=12, name='filename', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x6f, 0x6c, 0x64]), size=12,
                max_len=12, name='filename1', fuzzable=True)
    session.connect(s_get('Command_File_Name_Change'))


        #文件数据校核
def fuzzing_Command_File_Data_Check(session):
    s_initialize(name="Command_File_Data_Check")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x09]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x6e, 0x65, 0x77]), size=12,
                max_len=12, name='filename', fuzzable=True)
    session.connect(s_get('Command_File_Data_Check'))


        #内存区域文件传输
def fuzzing_Command_Memory_Area_File_Transfer(session):
    s_initialize(name="Command_Memory_Area_File_Transfer")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x0a]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name='Parameter_code', fuzzable=True)
        s_bytes(value=bytes([0x81]), size=1, max_len=1, name='Memory_Area_code', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x01]), size=3, max_len=3, name='Beginning_address', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Number_of_items', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x65, 0x78, 0x65]), size=12,
                max_len=12, name='filename', fuzzable=True)

    session.connect(s_get('Command_Memory_Area_File_Transfer'))

        #参数区域文件传输
def fuzzing_Command_Parameter_Area_File_Transfer(session):
    s_initialize(name="Command_Parameter_Area_File_Transfer")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x0b]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Parameter_code', fuzzable=True)
        s_bytes(value=bytes([0x81,0x10]), size=2, max_len=2, name='Memory_Area_code', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Beginning_address', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name='Number_words_or_bytes', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x65, 0x78, 0x65]), size=12,
                max_len=12, name='filename', fuzzable=True)

    session.connect(s_get('Command_Parameter_Area_File_Transfer'))

        #程序区域文件传输
def fuzzing_Command_Program_Area_File_Transfer(session):
    s_initialize(name="Command_Program_Area_File_Transfer")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x0c]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Parameter_code', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00]), size=2, max_len=2, name='Program_number', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x0e,0x00]), size=4, max_len=4, name='Beginning_word', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00,0xff]), size=4, max_len=4, name='Number_of_bytes', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name='Disk_no', fuzzable=True)
        s_bytes(value=bytes([0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x65, 0x78, 0x65]), size=12,
                max_len=12, name='filename', fuzzable=True)
    session.connect(s_get('Command_Program_Area_File_Transfer'))

        #文件内存索引读取
def fuzzing_Command_File_Memory_Index_Read(session):
    s_initialize(name="Command_File_Memory_Index_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x0f]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='Beginning_block_number', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='number_of_blocks', fuzzable=True)

    session.connect(s_get('Command_File_Memory_Index_Read'))

        #文件内存块读取
def fuzzing_Command_File_Memory_Read(session):
    s_initialize(name="Command_File_Memory_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x10]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='block_number', fuzzable=True)
    session.connect(s_get('Command_File_Memory_Read'))

        #文件内存块写入
def fuzzing_Command_File_Memory_Write(session):
    s_initialize(name="Command_File_Memory_Write")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x22, 0x11]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0xc3]), size=1, max_len=1, name='Data_type', fuzzable=True)
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name='Control_data', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='block_number', fuzzable=True)
        s_bytes(value=bytes([0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,
                             0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41,0x41, 0x41]), size=256, max_len=256, name='Data', fuzzable=True)
    session.connect(s_get('Command_File_Memory_Write'))

        #强制设置/重置
def fuzzing_Command_Forced_set_Reset(session):
    s_initialize(name="Command_Forced_set_Reset")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x23, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name='NO_of_bits_flags', fuzzable=True)
        s_bytes(value=bytes([0x80, 0x00]), size=2, max_len=2, name='Set_reset_specification', fuzzable=True)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Memory_area_code', fuzzable=True)
        s_bytes(value=bytes([0x00,0x00,0x01]), size=3, max_len=3, name='Bit_flag', fuzzable=True)
    session.connect(s_get('Command_Forced_set_Reset'))


        #取消强制设置/重置
def fuzzing_Command_Force_set_Reset_Cancel(session):
    s_initialize(name="Command_Force_set_Reset_Cancel")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x23, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
    session.connect(s_get('Command_Force_set_Reset_Cancel'))

        #多强制状态读取
def fuzzing_Command_Multiple_Forced_Status_Read(session):
    s_initialize(name="Command_Multiple_Forced_Status_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x23, 0x0a]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='Memory_Area_code', fuzzable=True)
        s_bytes(value=bytes([0x00, 0x00,0x00]), size=3, max_len=3, name='Beginning_address', fuzzable=True)
        s_bytes(value=bytes([0x01, 0x01]), size=2, max_len=2, name='Number_words_or_bytes', fuzzable=True)
    session.connect(s_get('Command_Multiple_Forced_Status_Read'))


        #名称设置
def fuzzing_Command_Name_Set(session):
    s_initialize(name="Command_Name_Set")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x26, 0x01]), size=2, max_len=2, name='Command_CODE', fuzzable=False)
        s_bytes(value=bytes([0x6e,0x61,0x6d,0x65,0x73,0x65,0x74,0x31]), size=8, max_len=8, name='Memory_Area_code', fuzzable=True)
    session.connect(s_get('Command_Name_Set'))

        #名称删除
def fuzzing_Command_Name_Delete(session):
    s_initialize(name="Command_Name_Delete")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x26, 0x02]), size=2, max_len=2, name='Command_CODE', fuzzable=False)

    session.connect(s_get('Command_Name_Delete'))

        #名称读取
def fuzzing_Command_Name_Read(session):
    s_initialize(name="Command_Name_Read")
    with s_block("FINS_Header"):
        s_bytes(value=bytes([0x80]), size=1, max_len=1, name='OMRON_icf_field', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Reserved', fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name='Gateway_count', fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Destination_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_network_address', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_node_number', fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name='Source_unit_address', fuzzable=True)
        s_bytes(value=bytes([0x7a]), size=1, max_len=1, name='Service_ID', fuzzable=True)
        s_bytes(value=bytes([0x26, 0x03]), size=2, max_len=2, name='Command_CODE', fuzzable=False)

    session.connect(s_get('Command_Name_Read'))



if __name__ == "__main__":
    fuzzing_main()