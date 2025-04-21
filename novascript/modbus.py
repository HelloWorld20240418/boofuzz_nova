
host_ip = ''
host_port = 502


def fuzzing_main():
    session = Session(target=Target(connection=TCPSocketConnection(host_ip, host_port)), nova_session_param=nova_session_param)
    fuzzing_modbus_run(session=session)
    fuzzing_read_coils(session=session)
    fuzzing_read_discrete_inputs(session=session)
    fuzzing_read_holding_registers(session=session)
    fuzzing_read_input_registers(session=session)
    fuzzing_write_single_coil(session=session)
    fuzzing_write_single_register(session=session)
    fuzzing_write_multiple_coils(session=session)
    fuzzing_write_multiple_registers(session=session)
    fuzzing_modbus_stop(session=session)
    session.fuzz()


# ---------------run----------------#
def fuzzing_modbus_run(session):
    s_initialize(name="Moubus_RUN")
    with s_block("Moubos/tcp"):
        s_bytes(value=bytes([0Xa4, 0xc2]), size=2, max_len=2, name='Transaction_Identifier', fuzzable=True)
        s_bytes(value=bytes([0X00, 0x00]), size=2, max_len=2, name='Protocol', fuzzable=False)
        s_bytes(value=bytes([0x00, 0X06]), size=2, max_len=2, name='Length', fuzzable=False)
        s_bytes(value=bytes([0X00]), size=1, max_len=1, name='unit_identifier', fuzzable=False)
    with s_block("Moubos"):
        s_bytes(value=bytes([0X5a]), size=1, max_len=1, name='function_code', fuzzable=False)
        s_bytes(value=bytes([0Xe6, 0x40, 0xff, 0x00]), size=4, max_len=4, name='Data', fuzzable=False)
    session.connect(s_get('Moubus_RUN'))


def fuzzing_read_coils(session):
    # ---------------Read Coils---------------#
    s_initialize(name="Read Coils")
    with s_block("Modbus/TCP"):
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Transaction_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Protocol_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Unit_Identifier", fuzzable=False)
    with s_block("Modbus"):
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name="Function_Code_Read_Coils", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Reference Number", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Bit Count", fuzzable=True)
    session.connect(s_get('Read Coils'))


def fuzzing_read_discrete_inputs(session):
    # ---------------Read Discrete Inputs---------------#
    s_initialize(name="Read Discrete Inputs")
    with s_block("Modbus/TCP"):
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Transaction_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Protocol_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Unit_Identifier", fuzzable=False)
    with s_block("Modbus"):
        s_bytes(value=bytes([0x02]), size=1, max_len=1, name="Function_Code_Read_Discrete_Inputs", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Reference Number", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Bit Count", fuzzable=True)
    session.connect(s_get('Read Discrete Inputs'))


def fuzzing_read_holding_registers(session):
    # ---------------Read Holding Registers---------------#
    s_initialize(name="Read Holding Registers")
    with s_block("Modbus/TCP"):
        s_bytes(value=bytes([0x00, 0x02]), size=2, max_len=2, name="Transaction_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Protocol_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Unit_Identifier", fuzzable=False)
    with s_block("Modbus"):
        s_bytes(value=bytes([0x03]), size=1, max_len=1, name="Function_Code_Read_Holding_Registers", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Reference Number", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Word Count", fuzzable=True)
    session.connect(s_get('Read Holding Registers'))


def fuzzing_read_input_registers(session):
    # ---------------Read Input Registers---------------#
    s_initialize(name="Read Input Registers")
    with s_block("Modbus/TCP"):
        s_bytes(value=bytes([0x00, 0x03]), size=2, max_len=2, name="Transaction_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Protocol_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Unit_Identifier", fuzzable=False)
    with s_block("Modbus"):
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="Function_Code_Read_Input_Registers", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Reference Number", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Word Count", fuzzable=True)
    session.connect(s_get('Read Input Registers'))


def fuzzing_write_single_coil(session):
    # ---------------Write Single Coil---------------#
    s_initialize(name="Write Single Coil")
    with s_block("Modbus/TCP"):
        s_bytes(value=bytes([0x00, 0x04]), size=2, max_len=2, name="Transaction_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Protocol_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Unit_Identifier", fuzzable=False)
    with s_block("Modbus"):
        s_bytes(value=bytes([0x05]), size=1, max_len=1, name="Function_Code_Write_Single_Coil", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Reference Number", fuzzable=False)
        s_bytes(value=bytes([0xff, 0x00]), size=2, max_len=2, name="Data", fuzzable=True)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Padding", fuzzable=True)
    session.connect(s_get('Write Single Coil'))


def fuzzing_write_single_register(session):
    # ---------------Write Single Register---------------#
    s_initialize(name="Write Single Register")
    with s_block("Modbus/TCP"):
        s_bytes(value=bytes([0x00, 0x05]), size=2, max_len=2, name="Transaction_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Protocol_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Unit_Identifier", fuzzable=False)
    with s_block("Modbus"):
        s_bytes(value=bytes([0x06, 0x00, 0x00, 0x00, 0x01]), size=5, max_len=5,
                name="Function_Code_Write_Single_Register", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Reference Number", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Data", fuzzable=True)
    session.connect(s_get('Write Single Register'))


def fuzzing_write_multiple_coils(session):
    # ---------------Write Multiple Coils---------------#
    s_initialize(name="Write Multiple Coils")
    with s_block("Modbus/TCP"):
        s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="Transaction_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Protocol_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x09]), size=2, max_len=2, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Unit_Identifier", fuzzable=False)
    with s_block("Modbus"):
        s_bytes(value=bytes([0x0f]), size=1, max_len=1, name="Function_Code_Write_Multiple_Coils", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Reference_Number", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Bit_Count", fuzzable=False)
        s_bytes(value=bytes([0x02]), size=1, max_len=2, name="Byte_Count", fuzzable=True)
        s_bytes(value=bytes([0xff, 0x03]), size=2, max_len=2, name="Data", fuzzable=True)
    session.connect(s_get('Write Multiple Coils'))


def fuzzing_write_multiple_registers(session):
    # ---------------Write Multiple Registers---------------#
    s_initialize(name="Write Multiple Registers")
    with s_block("Modbus/TCP"):
        s_bytes(value=bytes([0x00, 0x07]), size=2, max_len=2, name="Transaction_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Protocol_Identifier", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x1b]), size=2, max_len=2, name="Length", fuzzable=False)
        s_bytes(value=bytes([0x00]), size=1, max_len=1, name="Unit_Identifier", fuzzable=False)
    with s_block("Modbus"):
        s_bytes(value=bytes([0x10]), size=1, max_len=1, name="Function_Code_Write_Multiple_Registers",
                fuzzable=False)
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="Reference_Number", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x0a]), size=2, max_len=2, name="Word_Count", fuzzable=True)
        s_bytes(value=bytes([0x14]), size=1, max_len=2, name="Byte_Count", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number0", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_0", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number1", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_1", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number2", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_2", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number3", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_3", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number4", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_4", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number5", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_5", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number6", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_6", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number7", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_7", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number8", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_8", fuzzable=False)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Number9", fuzzable=True)
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="Register_Value_(UINT16)_9", fuzzable=True)
    session.connect(s_get('Write Multiple Registers'))


def fuzzing_modbus_stop(session):
    # ---------------stop----------------#
    s_initialize(name="Moubus_STOP")
    with s_block("Moubos/tcp"):
        s_bytes(value=bytes([0X23, 0x9f]), size=2, max_len=2, name='Transaction_Identifier', fuzzable=True)
        s_bytes(value=bytes([0X00, 0x00]), size=2, max_len=2, name='Protocol', fuzzable=False)
        s_bytes(value=bytes([0x00, 0X06]), size=2, max_len=2, name='Length', fuzzable=False)
        s_bytes(value=bytes([0X00]), size=1, max_len=1, name='unit_identifier', fuzzable=False)
    with s_block("Moubos"):
        s_bytes(value=bytes([0X5a]), size=1, max_len=1, name='function_code', fuzzable=False)
        s_bytes(value=bytes([0Xe6, 0x41, 0xff, 0x00]), size=4, max_len=4, name='Data', fuzzable=True)
    session.connect(s_get('Moubus_STOP'))


if __name__ == '__main__':
    fuzzing_main()
